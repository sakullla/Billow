// Controlled WireGuard peer for the Rust transport.
//
// It is a userspace WireGuard device built from the locked
// github.com/metacubex/wireguard-go (the device Mihomo v1.19.34 runs behind
// its `wireguard` outbound) with a fake TUN: instead of an operating-system
// interface the TUN answers IPv4 ICMP echo requests to 10.13.13.1 and echoes
// IPv4 UDP datagrams back. That keeps the peer a real WireGuard implementation
// while needing no root, no TUN driver and no IP stack.
//
// The peer prints one READY line with its UDP port and base64 public key:
//
//	READY <port> <base64-public-key>
//
// and exits on SIGINT/SIGTERM.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"
	"golang.org/x/crypto/curve25519"
)

type tcpConn struct {
	sndNxt uint32
	rcvNxt uint32
}

type echoTun struct {
	inbound chan []byte
	events  chan tun.Event
	closed  chan struct{}
	once    sync.Once
	mtu     int
	mu      sync.Mutex
	tcp     map[string]*tcpConn
}

func newEchoTun(mtu int) *echoTun {
	t := &echoTun{
		inbound: make(chan []byte, 64),
		events:  make(chan tun.Event, 1),
		closed:  make(chan struct{}),
		mtu:     mtu,
		tcp:     make(map[string]*tcpConn),
	}
	t.events <- tun.EventUp
	return t
}

func (t *echoTun) File() *os.File { return nil }

func (t *echoTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-t.inbound:
		if len(bufs) == 0 || len(bufs[0])-offset < len(packet) {
			return 0, fmt.Errorf("read buffer too small for %d bytes", len(packet))
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func (t *echoTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		replies := echoReply(packet)
		if len(packet) > 9 && packet[9] == 6 {
			t.mu.Lock()
			replies = tcpReply(packet, t.tcp)
			t.mu.Unlock()
		}
		for _, reply := range replies {
			select {
			case t.inbound <- reply:
			default:
			}
		}
	}
	return len(bufs), nil
}

func (t *echoTun) MTU() (int, error)        { return t.mtu, nil }
func (t *echoTun) Name() (string, error)    { return "billow-wg-peer", nil }
func (t *echoTun) Events() <-chan tun.Event { return t.events }
func (t *echoTun) BatchSize() int           { return 1 }
func (t *echoTun) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// echoReply turns an IPv4 ICMP echo request into the corresponding reply, and
// echoes an IPv4 UDP datagram back to its sender. Both repair the IPv4 header
// checksum; UDP also repairs its pseudo-header checksum.
// echoReply returns the echoes for one ICMP/UDP packet (TCP is handled by
// tcpReply, which keeps per-connection sequence state).
func echoReply(packet []byte) [][]byte {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return nil
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || len(packet) < headerLen+8 {
		return nil
	}
	if packet[9] == 17 {
		if reply := udpReply(packet, headerLen); reply != nil {
			return [][]byte{reply}
		}
		return nil
	}
	if packet[9] != 1 || packet[headerLen] != 8 {
		return nil
	}
	reply := make([]byte, len(packet))
	copy(reply, packet)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[8] = 64
	reply[headerLen] = 0   // ICMP type: echo reply
	reply[headerLen+1] = 0 // ICMP code
	reply[headerLen+2], reply[headerLen+3] = 0, 0
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], ipChecksum(reply[:headerLen]))
	binary.BigEndian.PutUint16(reply[headerLen+2:headerLen+4], icmpChecksum(reply[headerLen:]))
	return [][]byte{reply}
}

// tcpReply is a deliberately small TCP responder for the controlled peer: it
// completes the handshake, echoes every data segment and closes on FIN. It is
// not a general TCP implementation (no retransmit, reordering or window
// management); it exists so the Rust side can prove its smoltcp connection
// through the real WireGuard device.
func tcpReply(packet []byte, connections map[string]*tcpConn) [][]byte {
	if packet[0]>>4 != 4 {
		return nil
	}
	headerLen := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLen < 20 || totalLen < headerLen+20 || totalLen > len(packet) {
		return nil
	}
	tcp := packet[headerLen:totalLen]
	if len(tcp) < 20 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	flags := tcp[13]
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return nil
	}
	payload := tcp[doff:]
	src, dst := packet[12:16], packet[16:20]
	key := fmt.Sprintf("%d-%d", srcPort, dstPort)
	conn := connections[key]
	if flags&0x02 != 0 { // SYN
		conn = &tcpConn{rcvNxt: seq + 1, sndNxt: binary.BigEndian.Uint32(src) ^ uint32(srcPort) ^ 0x4000}
		connections[key] = conn
		reply := buildTCP(dst, src, dstPort, srcPort, conn.sndNxt, conn.rcvNxt, 0x12, nil, true)
		conn.sndNxt++
		if reply == nil {
			return nil
		}
		return [][]byte{reply}
	}
	if conn == nil {
		return nil
	}
	var replies [][]byte
	if len(payload) > 0 {
		conn.rcvNxt = seq + uint32(len(payload))
		if reply := buildTCP(dst, src, dstPort, srcPort, conn.sndNxt, conn.rcvNxt, 0x18, payload, false); reply != nil {
			conn.sndNxt += uint32(len(payload))
			replies = append(replies, reply)
		}
	}
	if flags&0x01 != 0 { // FIN
		conn.rcvNxt = seq + uint32(len(payload)) + 1
		if reply := buildTCP(dst, src, dstPort, srcPort, conn.sndNxt, conn.rcvNxt, 0x11, nil, false); reply != nil {
			conn.sndNxt++
			replies = append(replies, reply)
		}
		delete(connections, key)
	}
	return replies
}

func buildTCP(src, dst []byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, syn bool) []byte {
	optionLen := 0
	if syn {
		optionLen = 4
	}
	tcpLen := 20 + optionLen + len(payload)
	tcp := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte((20 + optionLen) / 4 << 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	if syn {
		tcp[20] = 2 // MSS
		tcp[21] = 4
		binary.BigEndian.PutUint16(tcp[22:24], 1360)
	}
	copy(tcp[20+optionLen:], payload)
	checksum := tcpChecksum(src, dst, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], checksum)
	return buildIPv4(src, dst, 6, tcp)
}

func tcpChecksum(src, dst, segment []byte) uint16 {
	var sum uint32
	add := func(data []byte) {
		for i := 0; i+1 < len(data); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		}
		if len(data)%2 == 1 {
			sum += uint32(data[len(data)-1]) << 8
		}
	}
	add(src)
	add(dst)
	sum += 6
	sum += uint32(len(segment))
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildIPv4(src, dst []byte, protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[6] = 0x40
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], src)
	copy(packet[16:20], dst)
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum(packet[:20]))
	copy(packet[20:], payload)
	return packet
}

func udpReply(packet []byte, headerLen int) []byte {
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < headerLen+8 || totalLen > len(packet) {
		return nil
	}
	udpLen := int(binary.BigEndian.Uint16(packet[headerLen+4 : headerLen+6]))
	if udpLen < 8 || headerLen+udpLen > totalLen {
		return nil
	}
	reply := make([]byte, totalLen)
	copy(reply, packet[:totalLen])
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[8] = 64
	srcPort := binary.BigEndian.Uint16(reply[headerLen : headerLen+2])
	dstPort := binary.BigEndian.Uint16(reply[headerLen+2 : headerLen+4])
	binary.BigEndian.PutUint16(reply[headerLen:headerLen+2], dstPort)
	binary.BigEndian.PutUint16(reply[headerLen+2:headerLen+4], srcPort)
	reply[headerLen+6], reply[headerLen+7] = 0, 0
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], ipChecksum(reply[:headerLen]))
	checksum := udpChecksum(reply[12:20], reply[headerLen:headerLen+udpLen])
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(reply[headerLen+6:headerLen+8], checksum)
	return reply
}

// udpChecksum includes the IPv4 pseudo-header (src, dst, zero, protocol, len).
func udpChecksum(addresses, datagram []byte) uint16 {
	var sum uint32
	add := func(data []byte) {
		for i := 0; i+1 < len(data); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		}
		if len(data)%2 == 1 {
			sum += uint32(data[len(data)-1]) << 8
		}
	}
	add(addresses[:8])
	sum += 17
	sum += uint32(len(datagram))
	add(datagram)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func icmpChecksum(message []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(message); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(message[i : i+2]))
	}
	if len(message)%2 == 1 {
		sum += uint32(message[len(message)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func decodeKey(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("key must be base64 of 32 bytes")
	}
	return hex.EncodeToString(raw), nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	clientKey := flag.String("client-key", "", "base64 client public key")
	serverKey := flag.String("server-key", "", "base64 server private key (generated when empty)")
	presharedKey := flag.String("preshared-key", "", "base64 pre-shared key (optional)")
	mtu := flag.Int("mtu", 1420, "TUN MTU")
	flag.Parse()

	if *clientKey == "" {
		fmt.Fprintln(os.Stderr, "-client-key is required")
		os.Exit(2)
	}
	clientHex, err := decodeKey(*clientKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client-key: %v\n", err)
		os.Exit(2)
	}
	var private [32]byte
	if *serverKey == "" {
		if _, err := rand.Read(private[:]); err != nil {
			fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
			os.Exit(1)
		}
	} else {
		hexKey, err := decodeKey(*serverKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "server-key: %v\n", err)
			os.Exit(2)
		}
		raw, _ := hex.DecodeString(hexKey)
		copy(private[:], raw)
	}
	// WireGuard clamps the private scalar and derives the public key with
	// Curve25519 over the base point (X25519 does the clamping again).
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	publicBytes, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive public key: %v\n", err)
		os.Exit(1)
	}
	var public [32]byte
	copy(public[:], publicBytes)

	_, portText, found := strings.Cut(*listen, ":")
	if !found {
		fmt.Fprintln(os.Stderr, "listen address needs host:port")
		os.Exit(2)
	}
	port := 0
	fmt.Sscanf(portText, "%d", &port)

	dev := device.NewDevice(newEchoTun(*mtu), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg-peer: "), runtime.NumCPU())
	conf := fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\npublic_key=%s\n",
		hex.EncodeToString(private[:]), port, clientHex,
	)
	if *presharedKey != "" {
		pskHex, err := decodeKey(*presharedKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "preshared-key: %v\n", err)
			os.Exit(2)
		}
		conf += "preshared_key=" + pskHex + "\n"
	}
	conf += "allowed_ip=10.13.13.2/32\n"
	if err := dev.IpcSet(conf); err != nil {
		fmt.Fprintf(os.Stderr, "IpcSet: %v\n", err)
		os.Exit(1)
	}
	if err := dev.Up(); err != nil {
		fmt.Fprintf(os.Stderr, "Up: %v\n", err)
		os.Exit(1)
	}
	current, err := dev.IpcGet()
	if err != nil {
		fmt.Fprintf(os.Stderr, "IpcGet: %v\n", err)
		os.Exit(1)
	}
	actualPort := 0
	for _, line := range strings.Split(current, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			fmt.Sscanf(value, "%d", &actualPort)
		}
	}
	if actualPort == 0 {
		fmt.Fprintln(os.Stderr, "device did not report a listen port")
		os.Exit(1)
	}
	fmt.Printf("READY %d %s\n", actualPort, base64.StdEncoding.EncodeToString(public[:]))
	_ = os.Stdout.Sync()
	select {}
}
