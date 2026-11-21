// ZeroTier VL1 peer used by T19. It is the locked `metacubex/zerotier-go`
// implementation parsing the Rust client's HELLO and building the OK reply,
// so the armor, identity encoding and endpoint layout are checked against the
// same code the pinned Mihomo runs.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	ZT "github.com/metacubex/zerotier-go"
)

func parseInet(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("short endpoint")
	}
	switch data[0] {
	case 0:
		return 1, nil
	case 4:
		if len(data) < 7 {
			return 0, fmt.Errorf("short IPv4 endpoint")
		}
		return 7, nil
	case 6:
		if len(data) < 19 {
			return 0, fmt.Errorf("short IPv6 endpoint")
		}
		return 19, nil
	default:
		return 0, fmt.Errorf("bad endpoint tag")
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	mode := flag.String("mode", "ok", "ok, wrong-key, truncated")
	flag.Parse()

	identity, err := ZT.GenerateIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate identity:", err)
		os.Exit(1)
	}
	secret := identity.SecretString()
	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("READY %d %s\n", conn.LocalAddr().(*net.UDPAddr).Port, secret)

	buffer := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			continue
		}
		packet, err := ZT.ParsePacket(buffer[:n])
		if err != nil {
			fmt.Fprintln(os.Stderr, "parse:", err)
			continue
		}
		if packet.Verb() != ZT.VerbHello {
			fmt.Fprintln(os.Stderr, "verb:", packet.Verb())
			continue
		}
		payload := packet.Payload()
		identityOffset := 1 + 1 + 1 + 2 + 8
		if len(payload) < identityOffset {
			continue
		}
		clientIdentity, consumed, err := ZT.ParseIdentityBinary(payload[identityOffset:])
		if err != nil || clientIdentity.Address() != packet.Source() {
			fmt.Fprintln(os.Stderr, "identity:", err, "source", packet.Source())
			continue
		}
		key, err := identity.Agree(clientIdentity)
		if err != nil {
			continue
		}
		if *mode == "truncated" {
			_, _ = conn.WriteTo([]byte{0x01, 0x02, 0x03}, remote)
			continue
		}
		if err := packet.Dearmor(key[:]); err != nil {
			fmt.Fprintln(os.Stderr, "dearmor:", err)
			continue
		}
		if err := clientIdentity.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "validate:", err)
			continue
		}
		pos := identityOffset + consumed
		if pos < len(payload) {
			endpointLength, err := parseInet(payload[pos:])
			if err == nil {
				pos += endpointLength
			}
		}
		if len(payload)-pos < 16 {
			continue
		}
		planetID := binary.BigEndian.Uint64(payload[pos:])
		planetTimestamp := binary.BigEndian.Uint64(payload[pos+8:])

		reply, err := ZT.NewPacket(clientIdentity.Address(), identity.Address(), ZT.VerbOK)
		if err != nil {
			continue
		}
		_ = reply.Append(byte(ZT.VerbHello))
		_ = reply.AppendUint64(packet.PacketID())
		_ = reply.AppendUint64(planetTimestamp)
		_ = reply.Append(ZT.ProtocolVersion, 0, 0)
		_ = reply.AppendUint16(0)
		_ = reply.Append(0) // no external surface in this controlled reply
		_ = reply.AppendUint16(0)
		_ = reply.AppendUint64(planetID)
		_ = reply.AppendUint64(planetTimestamp)
		if *mode == "wrong-key" {
			_ = reply.Armor(make([]byte, 48), true)
		} else {
			_ = reply.Armor(key[:], true)
		}
		_, _ = conn.WriteTo(reply.Bytes(), remote)
	}
}

