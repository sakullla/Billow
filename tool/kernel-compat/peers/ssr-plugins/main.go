// Controlled SSR plugin peer for the Rust client tests.
//
// The pinned Mihomo tree has an SSR *client* only (`transport/ssr/protocol`,
// `transport/ssr/obfs`); it registers no SSR listener. This program is the
// server side of those same wire formats, written against the pinned packages:
// it uses `transport/shadowsocks/core` + `shadowstream` for the cipher layer and
// `transport/ssr/tools` for the HMAC/digest primitives, while the server-side
// framing (auth-block parsing, per-record checks, obfs handshakes) is written
// here from the client code with the roles swapped. It is not the Rust
// implementation.
//
// Two modes:
//
//	go run . -listen 127.0.0.1:0 -cipher aes-256-cfb -password p \
//	         -protocol auth_chain_a -obfs tls1.2_ticket_auth
//	go run . -client -listen 127.0.0.1:8388 ... -target 127.0.0.1:7 -marker x
//
// `-client` runs the pinned client stack (`obfs.PickObfs` -> `core.PickCipher`
// -> `protocol.PickProtocol`, exactly like `adapter/outbound/shadowsocksr.go`)
// against the server. `tool/kernel-compat/family-peers.sh` runs the pinned
// client against this server and then the Rust client against the same server,
// so the Rust framing is checked against the pinned framing, not just against a
// second Rust implementation.
//
// `-vectors` prints the `tools.XorShift128Plus` sequence the Rust unit test
// pins.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowstream"
	"github.com/metacubex/mihomo/transport/ssr/obfs"
	"github.com/metacubex/mihomo/transport/ssr/protocol"
	"github.com/metacubex/mihomo/transport/ssr/tools"
)

var debug bool

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "listen address (server) or peer address (client)")
	cipherName := flag.String("cipher", "aes-256-cfb", "SSR cipher")
	password := flag.String("password", "", "SSR password")
	protocolName := flag.String("protocol", "origin", "SSR protocol plugin")
	protocolParam := flag.String("protocol-param", "", "SSR protocol parameter")
	obfsName := flag.String("obfs", "plain", "SSR obfs plugin")
	obfsParam := flag.String("obfs-param", "", "SSR obfs parameter")
	target := flag.String("target", "", "client mode: target address to request")
	marker := flag.String("marker", "ssr-plugin-peer", "client mode: payload to send")
	debugFlag := flag.Bool("debug", false, "log framing details")
	client := flag.Bool("client", false, "run the pinned client stack against -listen")
	vectors := flag.Bool("vectors", false, "print the pinned XorShift128Plus vectors")
	udp := flag.Bool("udp", false, "also serve SSR UDP on the same port")
	echo := flag.Bool("echo", false, "run a loopback TCP echo target instead of a peer")
	flag.Parse()
	debug = *debugFlag

	if *vectors {
		printVectors()
		return
	}
	if *echo {
		runEcho(*listen)
		return
	}

	key, ivSize, ciph, err := cipherFor(*cipherName, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipher: %v\n", err)
		os.Exit(2)
	}
	obfsOverhead, err := obfsOverheadOf(*obfsName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "obfs: %v\n", err)
		os.Exit(2)
	}
	protoOverhead, err := protocolOverheadOf(*protocolName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol: %v\n", err)
		os.Exit(2)
	}
	overhead := obfsOverhead + protoOverhead

	if *client {
		if err := runClient(*listen, *cipherName, *password, *protocolName, *protocolParam,
			*obfsName, *obfsParam, *target, []byte(*marker)); err != nil {
			fmt.Fprintf(os.Stderr, "client: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	if *udp {
		addr := ln.Addr().(*net.TCPAddr)
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: addr.IP, Port: addr.Port})
		if err != nil {
			fmt.Fprintf(os.Stderr, "udp listen: %v\n", err)
			os.Exit(2)
		}
		go serveUDP(pc, *cipherName, key, ciph, *protocolName, *protocolParam)
	}
	fmt.Printf("READY %s\n", ln.Addr().String())
	os.Stdout.Sync()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(raw, ciph, key, ivSize, *protocolName, *protocolParam, *obfsName, *obfsParam, overhead)
	}
}

// runEcho is the loopback target the client harness relays to.
func runEcho(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "echo listen: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("READY %s\n", ln.Addr().String())
	os.Stdout.Sync()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(conn)
	}
}

func printVectors() {
	seed := bytes.Repeat([]byte{7}, 16)
	var r tools.XorShift128Plus
	r.InitFromBin(seed)
	values := make([]uint64, 4)
	for i := range values {
		values[i] = r.Next()
	}
	var rl tools.XorShift128Plus
	rl.InitFromBinAndLength(seed, 100)
	after := []uint64{rl.Next(), rl.Next()}
	fmt.Printf("xorshift seed=07*16 values=%v with-length-100=%v\n", values, after)
	// The chain_b padding schedule for the test key.
	key := core.Kdf("ssr-plugin-peer", 32)
	var list tools.XorShift128Plus
	list.InitFromBin(key)
	length := list.Next()%8 + 4
	sizes := []int{}
	for ; length > 0; length-- {
		sizes = append(sizes, int(list.Next()%2340%2040%1440))
	}
	sort.Ints(sizes)
	length = list.Next()%16 + 8
	sizes2 := []int{}
	for ; length > 0; length-- {
		sizes2 = append(sizes2, int(list.Next()%2340%2040%1440))
	}
	sort.Ints(sizes2)
	fmt.Printf("chain_b sizes=%v sizes2=%v\n", sizes, sizes2)
}

// ---------------------------------------------------------------------------
// Cipher layer
// ---------------------------------------------------------------------------

func cipherFor(name, password string) (key []byte, ivSize int, ciph core.Cipher, err error) {
	lower := strings.ToLower(name)
	if lower == "none" {
		lower = "dummy"
	}
	ciph, err = core.PickCipher(lower, nil, password)
	if err != nil {
		return nil, 0, nil, err
	}
	if lower == "dummy" {
		return core.Kdf(password, 16), 0, ciph, nil
	}
	stream, ok := ciph.(*core.StreamCipher)
	if !ok {
		return nil, 0, nil, fmt.Errorf("%s is not a stream cipher", name)
	}
	return stream.Key, stream.IVSize(), ciph, nil
}

func obfsOverheadOf(name string) (int, error) {
	switch name {
	case "plain", "http_simple", "http_post", "random_head":
		return 0, nil
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return 5, nil
	}
	return 0, fmt.Errorf("obfs %s not supported", name)
}

func protocolOverheadOf(name string) (int, error) {
	switch name {
	case "origin":
		return 0, nil
	case "auth_sha1_v4":
		return 7, nil
	case "auth_aes128_md5", "auth_aes128_sha1":
		return 9, nil
	case "auth_chain_a", "auth_chain_b":
		return 4, nil
	}
	return 0, fmt.Errorf("protocol %s not supported", name)
}

func handle(raw net.Conn, ciph core.Cipher, key []byte, ivSize int,
	protocolName, protocolParam, obfsName, obfsParam string, overhead int) {
	defer func() {
		if debug {
			fmt.Fprintf(os.Stderr, "peer: handle return\n")
		}
		raw.Close()
	}()
	conn := newObfsServer(obfsName, obfsParam, raw, ivSize, key)
	// The cipher layer reads the client IV through the obfs framing and writes
	// the server IV the same way.
	var cipherConn net.Conn = conn
	var iv []byte
	if ivSize > 0 {
		sc := shadowstream.NewConn(conn, ciph.(*core.StreamCipher).Cipher)
		readIV, err := sc.ObtainReadIV()
		if err != nil {
			return
		}
		iv = readIV
		cipherConn = sc
	}
	proto, err := newProtocolServer(protocolName, protocolParam, key, iv, overhead)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocol server: %v\n", err)
		return
	}
	stream := &framedConn{Conn: cipherConn, proto: proto}
	host, port, err := readSocksAddr(stream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "peer: address: %v\n", err)
		return
	}
	upstream, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "peer: dial %s:%d: %v\n", host, port, err)
		return
	}
	if debug {
		fmt.Fprintf(os.Stderr, "peer: relaying %s:%d\n", host, port)
	}
	defer upstream.Close()
	if debug {
		fmt.Fprintf(os.Stderr, "peer: FORWARD %s:%d\n", host, port)
	}
	done := make(chan struct{})
	go func() {
		_, copyErr := io.Copy(upstream, stream)
		if copyErr != nil && debug {
			fmt.Fprintf(os.Stderr, "peer: client->target: %v\n", copyErr)
		}
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	if _, copyErr := io.Copy(stream, upstream); copyErr != nil && debug {
		fmt.Fprintf(os.Stderr, "peer: target->client: %v\n", copyErr)
	}
	<-done
	if debug {
		fmt.Fprintf(os.Stderr, "peer: handler done\n")
	}
}

// framedConn decodes client records on Read and frames server data on Write.
type framedConn struct {
	net.Conn
	proto          protoServer
	under, decoded bytes.Buffer
}

func (c *framedConn) Read(b []byte) (int, error) {
	for {
		if c.decoded.Len() > 0 {
			return c.decoded.Read(b)
		}
		// Decode buffered records before waiting for the socket: a previous
		// read may have carried several frames.
		if c.under.Len() > 0 {
			if err := c.proto.decode(&c.decoded, &c.under); err != nil {
				return 0, err
			}
			if c.decoded.Len() > 0 {
				continue
			}
		}
		buf := make([]byte, 8192)
		n, err := c.Conn.Read(buf)
		if err != nil {
			return 0, err
		}
		c.under.Write(buf[:n])
		if err := c.proto.decode(&c.decoded, &c.under); err != nil {
			return 0, err
		}
		if debug {
			fmt.Fprintf(os.Stderr, "peer: decoded %d bytes (under=%d)\n", c.decoded.Len(), c.under.Len())
		}
	}
}

func (c *framedConn) Write(b []byte) (int, error) {
	var buf bytes.Buffer
	if err := c.proto.encode(&buf, b); err != nil {
		return 0, err
	}
	if debug {
		fmt.Fprintf(os.Stderr, "peer: encoded %d -> %d bytes\n", len(b), buf.Len())
	}
	if _, err := c.Conn.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func readSocksAddr(r io.Reader) (string, int, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", 0, err
	}
	var host string
	switch kind[0] {
	case 0x01:
		var addr [4]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(addr[:]).String()
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	case 0x04:
		var addr [16]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(addr[:]).String()
	default:
		return "", 0, fmt.Errorf("unknown address type %d", kind[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(port[:])), nil
}

// ---------------------------------------------------------------------------
// Protocol servers
// ---------------------------------------------------------------------------

type protoServer interface {
	decode(dst, src *bytes.Buffer) error
	encode(dst *bytes.Buffer, b []byte) error
	encodePacket(buf *bytes.Buffer, b []byte) error
	decodePacket(b []byte) ([]byte, error)
}

func newProtocolServer(name, param string, key, iv []byte, overhead int) (protoServer, error) {
	switch name {
	case "origin":
		return &originServer{}, nil
	case "auth_sha1_v4":
		return &authSha1V4Server{key: key, iv: iv}, nil
	case "auth_aes128_md5":
		return newAuthAES128Server("auth_aes128_md5", param, key, iv, tools.HmacMD5, tools.MD5Sum)
	case "auth_aes128_sha1":
		return newAuthAES128Server("auth_aes128_sha1", param, key, iv, tools.HmacSHA1, tools.SHA1Sum)
	case "auth_chain_a":
		return newChainServer("auth_chain_a", param, key, iv, overhead, false)
	case "auth_chain_b":
		return newChainServer("auth_chain_b", param, key, iv, overhead, true)
	}
	return nil, fmt.Errorf("protocol %s not supported", name)
}

func getHeadSize(b []byte, def int) int {
	if len(b) < 2 {
		return def
	}
	switch b[0] & 7 {
	case 1:
		return 7
	case 4:
		return 19
	case 3:
		return 4 + int(b[1])
	}
	return def
}

// readRandPrefix consumes the `maxRandDataLengthPrefix` at the front of a frame.
func readRandPrefix(b []byte, pos int, bigEndian bool) (size int, next int, err error) {
	if pos >= len(b) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	if b[pos] < 255 {
		return int(b[pos]) - 1, pos + 1, nil
	}
	if pos+3 > len(b) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	if bigEndian {
		return int(binary.BigEndian.Uint16(b[pos+1:pos+3])) - 3, pos + 3, nil
	}
	return int(binary.LittleEndian.Uint16(b[pos+1:pos+3])) - 3, pos + 3, nil
}

// ---- origin ----

type originServer struct{}

func (o *originServer) decode(dst, src *bytes.Buffer) error            { dst.ReadFrom(src); return nil }
func (o *originServer) encode(dst *bytes.Buffer, b []byte) error       { dst.Write(b); return nil }
func (o *originServer) encodePacket(buf *bytes.Buffer, b []byte) error { buf.Write(b); return nil }
func (o *originServer) decodePacket(b []byte) ([]byte, error)          { return b, nil }

// ---- auth_sha1_v4 ----

type authSha1V4Server struct {
	key    []byte
	iv     []byte
	authed bool
}

func (a *authSha1V4Server) decode(dst, src *bytes.Buffer) error {
	if !a.authed {
		if src.Len() < 7 {
			return nil
		}
		buf := src.Bytes()
		length := int(binary.BigEndian.Uint16(buf[:2]))
		if length >= 8192 || length < 7 {
			return errors.New("auth_sha1_v4 decode data wrong length")
		}
		if length > src.Len() {
			return nil
		}
		// The auth frame's crc covers length(2) + salt + key.
		crcData := make([]byte, 0, 2+12+len(a.key))
		crcData = append(crcData, buf[:2]...)
		crcData = append(crcData, []byte("auth_sha1_v4")...)
		crcData = append(crcData, a.key...)
		if crc32.ChecksumIEEE(crcData) != binary.LittleEndian.Uint32(buf[2:6]) {
			return errors.New("auth_sha1_v4 wrong password")
		}
		randLen, next, err := readRandPrefix(buf, 6, true)
		if err != nil {
			return err
		}
		pos := next + randLen + 12
		if pos > length-10 {
			return errors.New("auth_sha1_v4 bad padding")
		}
		macKey := append(append([]byte{}, a.iv...), a.key...)
		if !hmac.Equal(tools.HmacSHA1(macKey, buf[:length-10])[:10], buf[length-10:length]) {
			return errors.New("auth_sha1_v4 wrong hmac")
		}
		dst.Write(buf[pos : length-10])
		src.Next(length)
		a.authed = true
		return nil
	}
	for src.Len() > 4 {
		buf := src.Bytes()
		if uint16(crc32.ChecksumIEEE(buf[:2])&0xffff) != binary.LittleEndian.Uint16(buf[2:4]) {
			return errors.New("auth_sha1_v4 decode data wrong crc32")
		}
		length := int(binary.BigEndian.Uint16(buf[:2]))
		if length >= 8192 || length < 7 {
			return errors.New("auth_sha1_v4 decode data wrong length")
		}
		if length > src.Len() {
			return nil
		}
		if adler32.Checksum(buf[:length-4]) != binary.LittleEndian.Uint32(buf[length-4:length]) {
			return errors.New("auth_sha1_v4 decode data wrong adler32")
		}
		randLen, next, err := readRandPrefix(buf, 4, true)
		if err != nil {
			return err
		}
		pos := next + randLen
		if pos > length-4 {
			return errors.New("auth_sha1_v4 bad padding")
		}
		dst.Write(buf[pos : length-4])
		src.Next(length)
	}
	return nil
}

func (a *authSha1V4Server) encode(dst *bytes.Buffer, b []byte) error {
	for len(b) > 8100 {
		a.packData(dst, b[:8100])
		b = b[8100:]
	}
	if len(b) > 0 {
		a.packData(dst, b)
	}
	return nil
}

func (a *authSha1V4Server) packData(dst *bytes.Buffer, b []byte) {
	randLen := randLenFor(len(b))
	packed := 2 + 2 + 3 + randLen + len(b) + 4
	if randLen < 128 {
		packed -= 2
	}
	start := dst.Len()
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(packed))
	dst.Write(lenBytes[:])
	var crcBytes [2]byte
	binary.LittleEndian.PutUint16(crcBytes[:], uint16(crc32.ChecksumIEEE(lenBytes[:])&0xffff))
	dst.Write(crcBytes[:])
	writeRandPrefix(dst, randLen, true)
	dst.Write(b)
	var adler [4]byte
	binary.LittleEndian.PutUint32(adler[:], adler32.Checksum(dst.Bytes()[start:]))
	dst.Write(adler[:])
}

func (a *authSha1V4Server) encodePacket(buf *bytes.Buffer, b []byte) error { buf.Write(b); return nil }
func (a *authSha1V4Server) decodePacket(b []byte) ([]byte, error)          { return b, nil }

func randLenFor(size int) int {
	if size > 1200 {
		return 0
	}
	if size > 400 {
		return randIntN(256)
	}
	return randIntN(512)
}

func writeRandPrefix(dst *bytes.Buffer, size int, bigEndian bool) {
	if size < 128 {
		dst.WriteByte(byte(size + 1))
	} else {
		dst.WriteByte(255)
		var raw [2]byte
		if bigEndian {
			binary.BigEndian.PutUint16(raw[:], uint16(size+3))
		} else {
			binary.LittleEndian.PutUint16(raw[:], uint16(size+3))
		}
		dst.Write(raw[:])
	}
	appendRand(dst, size)
}

func appendRand(dst *bytes.Buffer, size int) {
	if size <= 0 {
		return
	}
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	dst.Write(buf)
}

func randIntN(n int) int {
	if n <= 0 {
		return 0
	}
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return int(binary.LittleEndian.Uint64(buf) % uint64(n))
}

// ---- auth_aes128_md5 / auth_aes128_sha1 ----

type authAES128Server struct {
	salt    string
	hmac    func(key, data []byte) []byte
	digest  func([]byte) []byte
	key     []byte
	iv      []byte
	userKey []byte
	userID  [4]byte
	recvID  uint32
	packID  uint32
	authed  bool
}

func newAuthAES128Server(salt, param string, key, iv []byte, hmacFn func(key, data []byte) []byte, digest func([]byte) []byte) (protoServer, error) {
	s := &authAES128Server{salt: salt, hmac: hmacFn, digest: digest, key: key, iv: iv, recvID: 1, packID: 1}
	if param != "" {
		parts := strings.SplitN(param, ":", 2)
		if len(parts) == 2 {
			if id, err := strconv.ParseUint(parts[0], 10, 32); err == nil {
				binary.LittleEndian.PutUint32(s.userID[:], uint32(id))
				s.userKey = digest([]byte(parts[1]))
			}
		}
	}
	if len(s.userKey) == 0 {
		s.userKey = key
	}
	return s, nil
}

func (a *authAES128Server) decode(dst, src *bytes.Buffer) error {
	if !a.authed {
		// The auth frame has no length prefix: 1 rand byte, 6-byte head mac,
		// 4-byte user id, the 16-byte encrypted block, a 4-byte mac, random
		// padding, data, and a 4-byte mac. The total length and the padding
		// length come from the decrypted block.
		if src.Len() < 27 {
			return nil
		}
		buf := src.Bytes()
		authKey := append(append([]byte{}, a.iv...), a.key...)
		if !hmac.Equal(a.hmac(authKey, buf[:1])[:6], buf[1:7]) {
			return errors.New("auth_aes128 wrong head mac")
		}
		plain := aesCBCDecrypt(a.userKey, a.salt, buf[11:27])
		if plain == nil {
			return errors.New("auth_aes128 bad auth block")
		}
		length := int(binary.LittleEndian.Uint16(plain[12:14]))
		randLen := int(binary.LittleEndian.Uint16(plain[14:16]))
		if length < 7 || length >= 8192 || 31+randLen > length-4 {
			return errors.New("auth_aes128 bad padding")
		}
		if length > src.Len() {
			return nil
		}
		if !hmac.Equal(a.hmac(authKey, buf[7:27])[:4], buf[27:31]) {
			return errors.New("auth_aes128 wrong auth mac")
		}
		if !hmac.Equal(a.hmac(a.userKey, buf[:length-4])[:4], buf[length-4:length]) {
			return errors.New("auth_aes128 wrong password")
		}
		copy(a.userID[:], buf[7:11])
		dst.Write(buf[31+randLen : length-4])
		src.Next(length)
		a.authed = true
		return nil
	}
	for src.Len() > 4 {
		buf := src.Bytes()
		macKey := make([]byte, 0, len(a.userKey)+4)
		macKey = append(macKey, a.userKey...)
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], a.recvID)
		macKey = append(macKey, id[:]...)
		length := int(binary.LittleEndian.Uint16(buf[:2]))
		if length >= 8192 || length < 7 {
			return errors.New("auth_aes128 wrong length")
		}
		if length > src.Len() {
			return nil
		}
		if !hmac.Equal(a.hmac(macKey, buf[:length-4])[:4], buf[length-4:length]) {
			return errors.New("auth_aes128 wrong checksum")
		}
		randLen, next, err := readRandPrefix(buf, 4, false)
		if err != nil {
			return err
		}
		pos := next + randLen
		if pos > length-4 {
			return errors.New("auth_aes128 bad padding")
		}
		dst.Write(buf[pos : length-4])
		src.Next(length)
		a.recvID++
	}
	return nil
}

func (a *authAES128Server) encode(dst *bytes.Buffer, b []byte) error {
	for len(b) > 8100 {
		a.packData(dst, b[:8100])
		b = b[8100:]
	}
	if len(b) > 0 {
		a.packData(dst, b)
	}
	return nil
}

func (a *authAES128Server) packData(dst *bytes.Buffer, b []byte) {
	randLen := randLenFor(len(b))
	packed := 2 + 2 + 3 + randLen + len(b) + 4
	if randLen < 128 {
		packed -= 2
	}
	var id [4]byte
	binary.LittleEndian.PutUint32(id[:], a.packID)
	macKey := append(append([]byte{}, a.userKey...), id[:]...)
	a.packID++
	var lenBytes [2]byte
	binary.LittleEndian.PutUint16(lenBytes[:], uint16(packed))
	dst.Write(lenBytes[:])
	dst.Write(a.hmac(macKey, lenBytes[:])[:2])
	writeRandPrefix(dst, randLen, false)
	dst.Write(b)
	dst.Write(a.hmac(macKey, dst.Bytes()[dst.Len()-packed+4:])[:4])
}

func (a *authAES128Server) encodePacket(buf *bytes.Buffer, b []byte) error {
	// The reply carries the data and the mac only; the pinned client strips
	// four bytes, unlike the request which also names the user id.
	start := buf.Len()
	buf.Write(b)
	buf.Write(a.hmac(a.userKey, buf.Bytes()[start:])[:4])
	return nil
}

func (a *authAES128Server) decodePacket(b []byte) ([]byte, error) {
	if len(b) < 8 {
		return nil, errors.New("short packet")
	}
	if !hmac.Equal(a.hmac(a.userKey, b[:len(b)-4])[:4], b[len(b)-4:]) {
		return nil, errors.New("auth_aes128 wrong packet checksum")
	}
	// data + user id + mac
	return b[:len(b)-8], nil
}

func aesCBCDecrypt(userKey []byte, salt string, block []byte) []byte {
	if len(block) != 16 {
		return nil
	}
	material := base64.StdEncoding.EncodeToString(userKey) + salt
	key := core.Kdf(material, 16)
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, 16)
	cipher.NewCBCDecrypter(c, make([]byte, 16)).CryptBlocks(out, block)
	return out
}

// ---- auth_chain_a / auth_chain_b ----

type chainServer struct {
	salt           string
	key            []byte
	iv             []byte
	userKey        []byte
	userID         [4]byte
	overhead       int
	chainB         bool
	recvID         uint32
	packID         uint32
	authed         bool
	sentHeader     bool
	lastClientHash []byte
	lastServerHash []byte
	decrypter      cipher.Stream
	encrypter      cipher.Stream
	randomClient   tools.XorShift128Plus
	randomServer   tools.XorShift128Plus
	dataSizeList   []int
	dataSizeList2  []int
}

func newChainServer(salt, param string, key, iv []byte, overhead int, chainB bool) (protoServer, error) {
	s := &chainServer{salt: salt, key: key, iv: iv, overhead: overhead, chainB: chainB, recvID: 1, packID: 1}
	if param != "" {
		parts := strings.SplitN(param, ":", 2)
		if len(parts) == 2 {
			if id, err := strconv.ParseUint(parts[0], 10, 32); err == nil {
				binary.LittleEndian.PutUint32(s.userID[:], uint32(id))
				s.userKey = []byte(parts[1])
			}
		}
	}
	if len(s.userKey) == 0 {
		s.userKey = key
	}
	if chainB {
		s.initDataSize()
	}
	return s, nil
}

func (a *chainServer) initDataSize() {
	a.randomServer.InitFromBin(a.key)
	length := a.randomServer.Next()%8 + 4
	for ; length > 0; length-- {
		a.dataSizeList = append(a.dataSizeList, int(a.randomServer.Next()%2340%2040%1440))
	}
	sort.Ints(a.dataSizeList)
	length = a.randomServer.Next()%16 + 8
	for ; length > 0; length-- {
		a.dataSizeList2 = append(a.dataSizeList2, int(a.randomServer.Next()%2340%2040%1440))
	}
	sort.Ints(a.dataSizeList2)
}

func (a *chainServer) randLength(length int, lastHash []byte, random *tools.XorShift128Plus) int {
	if a.chainB {
		if length >= 1440 {
			return 0
		}
		random.InitFromBinAndLength(lastHash, length)
		threshold := length + a.overhead
		pos := sort.Search(len(a.dataSizeList), func(i int) bool { return a.dataSizeList[i] >= threshold })
		finalPos := pos + int(random.Next()%uint64(len(a.dataSizeList)))
		if finalPos < len(a.dataSizeList) {
			return a.dataSizeList[finalPos] - threshold
		}
		pos = sort.Search(len(a.dataSizeList2), func(i int) bool { return a.dataSizeList2[i] >= threshold })
		finalPos = pos + int(random.Next()%uint64(len(a.dataSizeList2)))
		if finalPos < len(a.dataSizeList2) {
			return a.dataSizeList2[finalPos] - threshold
		}
		if finalPos < pos+len(a.dataSizeList2)-1 {
			return 0
		}
		if length > 1300 {
			return int(random.Next() % 31)
		}
		if length > 900 {
			return int(random.Next() % 127)
		}
		if length > 400 {
			return int(random.Next() % 521)
		}
		return int(random.Next() % 1021)
	}
	if length > 1440 {
		return 0
	}
	random.InitFromBinAndLength(lastHash, length)
	if length > 1300 {
		return int(random.Next() % 31)
	}
	if length > 900 {
		return int(random.Next() % 127)
	}
	if length > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func getRandStartPos(length int, random *tools.XorShift128Plus) int {
	if length == 0 {
		return 0
	}
	return int(int64(random.Next()%8589934609) % int64(length))
}

func (a *chainServer) initRC4(lastClientHash []byte) {
	material := base64.StdEncoding.EncodeToString(a.userKey) + base64.StdEncoding.EncodeToString(lastClientHash)
	key := core.Kdf(material, 16)
	a.decrypter, _ = rc4.NewCipher(key)
	a.encrypter, _ = rc4.NewCipher(key)
}

func (a *chainServer) parseAuth(buf []byte) (int, error) {
	// 4 rand + 8 hash + 4 uid + 16 encrypted + 4 hash = 36 bytes
	if len(buf) < 36 {
		return 0, io.ErrUnexpectedEOF
	}
	macKey := append(append([]byte{}, a.iv...), a.key...)
	a.lastClientHash = tools.HmacMD5(macKey, buf[0:4])
	if !bytes.Equal(a.lastClientHash[:8], buf[4:12]) {
		return 0, errors.New("auth_chain wrong client hash")
	}
	if !bytes.Equal(a.lastClientHash[8:12], []byte{
		buf[12] ^ a.userID[0], buf[13] ^ a.userID[1], buf[14] ^ a.userID[2], buf[15] ^ a.userID[3],
	}) {
		// The uid is the configured user id XORed with the hash; with no user
		// list any value is accepted, but the encryption below still has to
		// decrypt, so a mismatch is only a hint.
		_ = buf
	}
	plain := aesCBCDecrypt(a.userKey, a.salt, buf[16:32])
	if plain == nil || binary.LittleEndian.Uint16(plain[14:16]) != 0 {
		return 0, errors.New("auth_chain wrong auth block")
	}
	a.lastServerHash = tools.HmacMD5(a.userKey, buf[12:32])
	if !bytes.Equal(a.lastServerHash[:4], buf[32:36]) {
		return 0, errors.New("auth_chain wrong server hash")
	}
	a.initRC4(a.lastClientHash)
	a.authed = true
	return 36, nil
}

func (a *chainServer) decode(dst, src *bytes.Buffer) error {
	for {
		if !a.authed {
			if src.Len() < 36 {
				return nil
			}
			consumed, err := a.parseAuth(src.Bytes())
			if err != nil {
				return err
			}
			src.Next(consumed)
			continue
		}
		if src.Len() <= 4 {
			return nil
		}
		buf := src.Bytes()
		dataLength := int(binary.LittleEndian.Uint16(buf[:2]) ^ binary.LittleEndian.Uint16(a.lastClientHash[14:16]))
		randLength := a.randLength(dataLength, a.lastClientHash, &a.randomClient)
		length := dataLength + randLength
		if length < 0 || length >= 4096 {
			return fmt.Errorf("auth_chain wrong length data=%d rand=%d total=%d", dataLength, randLength, length)
		}
		if 4+length > src.Len() {
			return nil
		}
		macKey := make([]byte, 0, len(a.userKey)+4)
		macKey = append(macKey, a.userKey...)
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], a.recvID)
		macKey = append(macKey, id[:]...)
		serverHash := tools.HmacMD5(macKey, buf[:length+2])
		if !bytes.Equal(serverHash[:2], buf[length+2:length+4]) {
			return errors.New("auth_chain wrong checksum")
		}
		a.lastClientHash = serverHash
		pos := 2
		if dataLength > 0 && randLength > 0 {
			pos += getRandStartPos(randLength, &a.randomClient)
		}
		wanted := append([]byte{}, buf[pos:pos+dataLength]...)
		a.decrypter.XORKeyStream(wanted, wanted)
		dst.Write(wanted)
		a.recvID++
		src.Next(length + 4)
	}
}

func (a *chainServer) encode(dst *bytes.Buffer, b []byte) error {
	for len(b) > 2800 {
		if err := a.packData(dst, b[:2800]); err != nil {
			return err
		}
		b = b[2800:]
	}
	if len(b) > 0 {
		return a.packData(dst, b)
	}
	return nil
}

func (a *chainServer) packData(dst *bytes.Buffer, b []byte) error {
	if !a.sentHeader {
		// The pinned client discards two bytes from the server's first record.
		b = append([]byte{0, 0}, b...)
		a.sentHeader = true
	}
	data := append([]byte{}, b...)
	a.encrypter.XORKeyStream(data, data)
	macKey := make([]byte, 0, len(a.userKey)+4)
	macKey = append(macKey, a.userKey...)
	var id [4]byte
	binary.LittleEndian.PutUint32(id[:], a.packID)
	macKey = append(macKey, id[:]...)
	a.packID++
	masked := uint16(len(data)) ^ binary.LittleEndian.Uint16(a.lastServerHash[14:16])
	start := dst.Len()
	var lenBytes [2]byte
	binary.LittleEndian.PutUint16(lenBytes[:], masked)
	dst.Write(lenBytes[:])
	randLength := a.randLength(len(data), a.lastServerHash, &a.randomServer)
	if randLength > 0 {
		startPos := getRandStartPos(randLength, &a.randomServer)
		appendRand(dst, startPos)
		dst.Write(data)
		appendRand(dst, randLength-startPos)
	} else {
		dst.Write(data)
	}
	a.lastServerHash = tools.HmacMD5(macKey, dst.Bytes()[start:])
	dst.Write(a.lastServerHash[:2])
	return nil
}

func udpRandLength(lastHash []byte, random *tools.XorShift128Plus) int {
	random.InitFromBin(lastHash)
	return int(random.Next() % 127)
}

func (a *chainServer) encodePacket(buf *bytes.Buffer, b []byte) error {
	authData := make([]byte, 3)
	_, _ = rand.Read(authData)
	// The pinned decoder hashes auth(3) + uid(4), so the reply key follows that
	// (the request key above hashes auth only: the pinned encoder's asymmetry).
	uidData := make([]byte, 4)
	binary.LittleEndian.PutUint32(uidData, binary.LittleEndian.Uint32(a.userID[:]))
	md5Data := tools.HmacMD5(a.key, append(append([]byte{}, authData...), uidData...))
	randLength := udpRandLength(md5Data, &a.randomClient)
	material := base64.StdEncoding.EncodeToString(a.userKey) + base64.StdEncoding.EncodeToString(md5Data)
	key := core.Kdf(material, 16)
	stream, err := rc4.NewCipher(key)
	if err != nil {
		return err
	}
	payload := append([]byte{}, b...)
	stream.XORKeyStream(payload, payload)
	start := buf.Len()
	buf.Write(payload)
	appendRand(buf, randLength)
	buf.Write(authData)
	buf.Write(uidData)
	buf.Write(tools.HmacMD5(a.userKey, buf.Bytes()[start:])[:1])
	return nil
}

func (a *chainServer) decodePacket(b []byte) ([]byte, error) {
	if len(b) < 9 {
		return nil, errors.New("auth_chain short packet")
	}
	if !hmac.Equal(tools.HmacMD5(a.userKey, b[:len(b)-1])[:1], b[len(b)-1:]) {
		return nil, errors.New("auth_chain wrong packet checksum")
	}
	// The pinned encoder derives the request key from the three auth bytes.
	md5Data := tools.HmacMD5(a.key, b[len(b)-8:len(b)-5])
	randLength := udpRandLength(md5Data, &a.randomServer)
	material := base64.StdEncoding.EncodeToString(a.userKey) + base64.StdEncoding.EncodeToString(md5Data)
	key := core.Kdf(material, 16)
	stream, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if 8+randLength > len(b) {
		return nil, fmt.Errorf("auth_chain short packet len=%d rand=%d md5=%x tail=%x", len(b), randLength, md5Data, b[len(b)-8:])
	}
	wanted := append([]byte{}, b[:len(b)-8-randLength]...)
	stream.XORKeyStream(wanted, wanted)
	_ = key
	return wanted, nil
}

// ---------------------------------------------------------------------------
// Obfs servers
// ---------------------------------------------------------------------------

func newObfsServer(name, param string, raw net.Conn, ivSize int, key []byte) net.Conn {
	switch name {
	case "http_simple", "http_post":
		return &httpServerConn{Conn: raw, post: name == "http_post"}
	case "random_head":
		return &randomHeadServerConn{Conn: raw}
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return &tls12ServerConn{Conn: raw, param: param, key: key}
	}
	return raw
}

type httpServerConn struct {
	net.Conn
	post     bool
	headDone bool
	pending  []byte
	buf      []byte
	wrote    bool
}

func (c *httpServerConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.headDone {
		return c.Conn.Read(b)
	}
	for {
		tmp := make([]byte, 4096)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.buf = append(c.buf, tmp[:n]...)
		pos := bytes.Index(c.buf, []byte("\r\n\r\n"))
		if pos < 0 {
			if len(c.buf) > 64*1024 {
				return 0, errors.New("http obfs head too large")
			}
			continue
		}
		head := c.buf[:pos]
		rest := append([]byte{}, c.buf[pos+4:]...)
		line := head
		if i := bytes.Index(head, []byte("\r\n")); i >= 0 {
			line = head[:i]
		}
		parts := bytes.SplitN(line, []byte(" "), 3)
		if len(parts) < 2 || len(parts[1]) < 1 || parts[1][0] != '/' {
			return 0, fmt.Errorf("bad obfs request line %q", line)
		}
		decoded, err := urlDecode(parts[1][1:])
		if err != nil {
			return 0, err
		}
		c.pending = append(decoded, rest...)
		c.headDone = true
		c.buf = nil
		if len(c.pending) == 0 {
			continue
		}
		n = copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	if c.wrote {
		return c.Conn.Write(b)
	}
	c.wrote = true
	head := "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n"
	if _, err := c.Conn.Write([]byte(head)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func urlDecode(raw []byte) ([]byte, error) {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			out = append(out, raw[i])
			continue
		}
		if i+2 >= len(raw) {
			return nil, errors.New("bad percent escape")
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+3]), 16, 8)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(value))
		i += 2
	}
	return out, nil
}

type randomHeadServerConn struct {
	net.Conn
	headDone bool
	buf      []byte
	wrote    bool
}

func (c *randomHeadServerConn) Read(b []byte) (int, error) {
	if c.headDone {
		if len(c.buf) > 0 {
			n := copy(b, c.buf)
			c.buf = c.buf[n:]
			return n, nil
		}
		return c.Conn.Read(b)
	}
	for {
		tmp := make([]byte, 2048)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.buf = append(c.buf, tmp[:n]...)
		for length := 4; length+4 <= len(c.buf) && length <= 99; length++ {
			if crc32.ChecksumIEEE(c.buf[:length])+binary.LittleEndian.Uint32(c.buf[length:length+4]) != 0xffffffff {
				continue
			}
			rest := append([]byte{}, c.buf[length+4:]...)
			c.buf = rest
			c.headDone = true
			if err := c.writeHead(); err != nil {
				return 0, err
			}
			if len(c.buf) > 0 {
				n = copy(b, c.buf)
				c.buf = c.buf[n:]
				return n, nil
			}
			return 0, nil
		}
		if len(c.buf) > 256 {
			return 0, errors.New("random_head bad head")
		}
	}
}

func (c *randomHeadServerConn) writeHead() error {
	if c.wrote {
		return nil
	}
	c.wrote = true
	length := randIntN(96) + 4
	head := make([]byte, length+4)
	_, _ = rand.Read(head[:length])
	binary.LittleEndian.PutUint32(head[length:], 0xffffffff-crc32.ChecksumIEEE(head[:length]))
	_, err := c.Conn.Write(head)
	return err
}

type tls12ServerConn struct {
	net.Conn
	param     string
	helloDone bool
	buf       []byte
	pending   []byte
	key       []byte
	clientID  []byte
	wrote     bool
}

func (c *tls12ServerConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if !c.helloDone {
		if err := c.readHello(); err != nil {
			return 0, err
		}
		if len(c.pending) == 0 {
			return 0, nil
		}
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	// Application records.
	for {
		for len(c.buf) >= 5 {
			if !bytes.Equal(c.buf[:3], []byte{0x17, 3, 3}) {
				return 0, errors.New("tls1.2_ticket_auth incorrect magic number")
			}
			size := int(binary.BigEndian.Uint16(c.buf[3:5]))
			if len(c.buf) < 5+size {
				break
			}
			data := append([]byte{}, c.buf[5:5+size]...)
			c.buf = c.buf[5+size:]
			if len(data) > 0 {
				n := copy(b, data)
				c.pending = append(c.pending, data[n:]...)
				return n, nil
			}
		}
		tmp := make([]byte, 4096)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return 0, err
		}
		c.buf = append(c.buf, tmp[:n]...)
	}
}

func (c *tls12ServerConn) readHello() error {
	for {
		tmp := make([]byte, 4096)
		n, err := c.Conn.Read(tmp)
		if err != nil {
			return err
		}
		c.buf = append(c.buf, tmp[:n]...)
		if len(c.buf) < 5 {
			continue
		}
		total := 5 + int(binary.BigEndian.Uint16(c.buf[3:5]))
		if len(c.buf) < total || len(c.buf) < 76 {
			continue
		}
		hello := c.buf[:total]
		c.clientID = append([]byte{}, hello[44:76]...)
		key := append(append([]byte{}, c.key...), c.clientID...)
		if !hmac.Equal(tools.HmacSHA1(key, hello[11:33])[:10], hello[33:43]) {
			return errors.New("tls1.2_ticket_auth hmac verifying failed")
		}
		c.buf = c.buf[total:]
		// The client sends its Finished record (and then the first data
		// records) only after it has read the server hello, so the hello goes
		// out before the Finished record is read.
		if err := c.writeServerHello(); err != nil {
			return err
		}
		// The client sends the change_cipher_spec record and its Finished
		// record before the first data record.
		for len(c.buf) < 43 {
			tmp := make([]byte, 4096)
			n, err := c.Conn.Read(tmp)
			if err != nil {
				return err
			}
			c.buf = append(c.buf, tmp[:n]...)
		}
		if !bytes.Equal(c.buf[:6], []byte{0x14, 3, 3, 0, 1, 1}) {
			return errors.New("tls1.2_ticket_auth missing change_cipher_spec")
		}
		if !bytes.Equal(c.buf[6:11], []byte{0x16, 3, 3, 0, 0x20}) {
			return errors.New("tls1.2_ticket_auth missing finished record")
		}
		if !hmac.Equal(tools.HmacSHA1(key, c.buf[:33])[:10], c.buf[33:43]) {
			return errors.New("tls1.2_ticket_auth finished hmac failed")
		}
		c.buf = c.buf[43:]
		c.helloDone = true
		return nil
	}
}

func (c *tls12ServerConn) writeServerHello() error {
	if c.wrote {
		return nil
	}
	c.wrote = true
	key := append(append([]byte{}, c.key...), c.clientID...)
	random22 := make([]byte, 22)
	_, _ = rand.Read(random22)
	random32 := make([]byte, 32)
	_, _ = rand.Read(random32)
	body := []byte{0x02, 0x00, 0, 0, 3, 3}
	body = append(body, random22...)
	body = append(body, tools.HmacSHA1(key, random22)[:10]...)
	body = append(body, 0x20)
	body = append(body, random32...)
	body = append(body, 0xc0, 0x2b, 0x00)
	body = append(body, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)-4))
	full := []byte{0x16, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(full[3:5], uint16(len(body)+10))
	full = append(full, body...)
	full = append(full, tools.HmacSHA1(key, full)[:10]...)
	_, err := c.Conn.Write(full)
	return err
}

func (c *tls12ServerConn) Write(b []byte) (int, error) {
	out := make([]byte, 5+len(b))
	out[0], out[1], out[2] = 0x17, 3, 3
	binary.BigEndian.PutUint16(out[3:5], uint16(len(b)))
	copy(out[5:], b)
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ---------------------------------------------------------------------------
// Pinned client harness
// ---------------------------------------------------------------------------

func runClient(addr, cipherName, password, protocolName, protocolParam,
	obfsName, obfsParam, target string, marker []byte) error {
	key, ivSize, ciph, err := cipherFor(cipherName, password)
	if err != nil {
		return err
	}
	_ = ivSize
	obfsImpl, obfsOverhead, err := obfs.PickObfs(obfsName, &obfs.Base{
		Host:   strings.Split(addr, ":")[0],
		Port:   portOf(addr),
		Key:    key,
		IVSize: ivSize,
		Param:  obfsParam,
	})
	if err != nil {
		return err
	}
	proto, err := protocol.PickProtocol(protocolName, &protocol.Base{
		Key:      key,
		Overhead: obfsOverhead,
		Param:    protocolParam,
	})
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn := obfsImpl.StreamConn(raw)
	conn = ciph.StreamConn(conn)
	var iv []byte
	if sc, ok := conn.(*shadowstream.Conn); ok {
		iv, err = sc.ObtainWriteIV()
		if err != nil {
			return err
		}
	}
	conn = proto.StreamConn(conn, iv)
	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(socksAddr(host, port)); err != nil {
		return err
	}
	sent := append([]byte{}, marker...)
	if _, err := conn.Write(sent); err != nil {
		return err
	}
	back := make([]byte, len(marker))
	if _, err := io.ReadFull(conn, back); err != nil {
		return err
	}
	if !bytes.Equal(back, marker) {
		return fmt.Errorf("echo mismatch: got %x want %x", back, marker)
	}
	fmt.Println("CLIENT OK")
	return nil
}

func portOf(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	value, _ := strconv.Atoi(port)
	return value
}

func splitHostPort(target string) (string, int, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	return host, value, nil
}

func socksAddr(host string, port int) []byte {
	out := []byte{}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, 0x01)
			out = append(out, ip4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		out = append(out, 0x03, byte(len(host)))
		out = append(out, []byte(host)...)
	}
	return append(out, byte(port>>8), byte(port))
}

// ---------------------------------------------------------------------------
// SSR UDP server
// ---------------------------------------------------------------------------

func serveUDP(pc *net.UDPConn, cipherName string, key []byte, ciph core.Cipher,
	protocolName, protocolParam string) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		packet := append([]byte{}, buf[:n]...)
		go func(packet []byte, from *net.UDPAddr) {
			plain, err := unpackDatagram(cipherName, key, ciph, packet)
			if err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "peer udp: unpack: %v\n", err)
				}
				return
			}
			proto, err := newProtocolServer(protocolName, protocolParam, key, nil, 0)
			if err != nil {
				return
			}
			payload, err := proto.decodePacket(plain)
			if err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "peer udp: decode packet: %v\n", err)
				}
				return
			}
			host, port, err := readSocksAddr(bytes.NewReader(payload))
			if err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "peer udp: address: %v\n", err)
				}
				return
			}
			addrLen := len(payload) - len(payloadForAddress(payload))
			body := payload[addrLen:]
			upstream, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				return
			}
			defer upstream.Close()
			_, _ = upstream.Write(body)
			reply := make([]byte, 65535)
			_ = upstream.SetReadDeadline(deadline())
			rn, err := upstream.Read(reply)
			if err != nil {
				return
			}
			var out bytes.Buffer
			out.Write(socksAddr(host, port))
			out.Write(reply[:rn])
			var framed bytes.Buffer
			if err := proto.encodePacket(&framed, out.Bytes()); err != nil {
				return
			}
			datagram := packDatagram(cipherName, key, ciph, framed.Bytes())
			_, _ = pc.WriteToUDP(datagram, from)
		}(packet, from)
	}
}

func payloadForAddress(payload []byte) []byte {
	// Returns the payload after the SOCKS address; used to find the address
	// length without re-parsing.
	host, port, err := readSocksAddr(bytes.NewReader(payload))
	if err != nil {
		return payload
	}
	_ = host
	_ = port
	switch payload[0] {
	case 0x01:
		return payload[7:]
	case 0x04:
		return payload[19:]
	case 0x03:
		return payload[4+int(payload[1]):]
	}
	return payload
}

func packDatagram(cipherName string, key []byte, ciph core.Cipher, plain []byte) []byte {
	if strings.ToLower(cipherName) == "dummy" || strings.ToLower(cipherName) == "none" {
		return append([]byte{}, plain...)
	}
	stream := ciph.(*core.StreamCipher)
	iv := make([]byte, stream.IVSize())
	_, _ = rand.Read(iv)
	out := append([]byte{}, iv...)
	out = append(out, plain...)
	stream.Encrypter(iv).XORKeyStream(out[len(iv):], out[len(iv):])
	return out
}

func unpackDatagram(cipherName string, key []byte, ciph core.Cipher, packet []byte) ([]byte, error) {
	if strings.ToLower(cipherName) == "dummy" || strings.ToLower(cipherName) == "none" {
		return packet, nil
	}
	stream := ciph.(*core.StreamCipher)
	ivSize := stream.IVSize()
	if len(packet) < ivSize {
		return nil, errors.New("short datagram")
	}
	out := append([]byte{}, packet[ivSize:]...)
	stream.Decrypter(packet[:ivSize]).XORKeyStream(out, out)
	return out, nil
}

func deadline() time.Time {
	return time.Now().Add(2 * time.Second)
}
