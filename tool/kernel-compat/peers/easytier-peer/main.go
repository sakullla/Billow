// EasyTier peer used by T19. `-mode core` runs the pinned EasyTier wasm core
// with `enable_encryption=false`; `-mode controlled` implements the same
// cleartext host/discovery frame and checks the advertised network-secret
// digest, which lets the test exercise the authentication boundary that the
// core performs later in its secure-datagram layer.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/easytier/easytier/easytier-go/platform"
	"github.com/easytier/easytier/easytier-go/proto/peer_rpc"
	"google.golang.org/protobuf/proto"
)

const magicCookie = 0xd1e1a5e1

type frame struct {
	src, dst uint32
	kind     uint8
	flags    uint8
	version  uint16
	body     []byte
}

func readFrame(conn net.Conn) (*frame, error) {
	var header [20]byte
	if _, err := io.ReadFull(conn, header[:4]); err != nil {
		return nil, err
	}
	total := binary.LittleEndian.Uint32(header[:4])
	if total < 16 || total > 1<<20 {
		return nil, fmt.Errorf("bad length %d", total)
	}
	record := make([]byte, total)
	if _, err := io.ReadFull(conn, record); err != nil {
		return nil, err
	}
	f := &frame{
		src:     binary.BigEndian.Uint32(record[0:4]),
		dst:     binary.BigEndian.Uint32(record[4:8]),
		kind:    record[8],
		flags:   record[9],
		version: binary.LittleEndian.Uint16(record[10:12]),
	}
	bodyLen := binary.LittleEndian.Uint32(record[12:16])
	if int(bodyLen) > len(record)-16 {
		return nil, fmt.Errorf("bad body length %d", bodyLen)
	}
	f.body = record[16 : 16+bodyLen]
	return f, nil
}

func writeFrame(conn net.Conn, f *frame) error {
	total := 16 + len(f.body)
	record := make([]byte, 4+total)
	binary.LittleEndian.PutUint32(record[0:4], uint32(total))
	binary.BigEndian.PutUint32(record[4:8], f.src)
	binary.BigEndian.PutUint32(record[8:12], f.dst)
	record[12] = f.kind
	record[13] = f.flags
	binary.LittleEndian.PutUint16(record[14:16], f.version)
	binary.LittleEndian.PutUint32(record[16:20], uint32(len(f.body)))
	copy(record[20:], f.body)
	_, err := conn.Write(record)
	return err
}

func controlled(listen, network, secret string, reject bool) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("READY %d\n", listener.Addr().(*net.TCPAddr).Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			request, err := readFrame(conn)
			if err != nil || request.kind != 2 {
				return
			}
			req := &peer_rpc.HandshakeRequest{}
			if err := proto.Unmarshal(request.body, req); err != nil || req.Magic != magicCookie {
				return
			}
			digest := sha256.Sum256([]byte(secret))
			if reject || req.NetworkName != network || string(req.NetworkSecretDigest) != string(digest[:]) {
				return
			}
			reply := &peer_rpc.HandshakeRequest{
				Magic:               magicCookie,
				MyPeerId:            request.src ^ 0x9e3779b9,
				Version:             1,
				Features:            []string{"liveness-echo-v1"},
				NetworkName:         network,
				NetworkSecretDigest: digest[:],
			}
			body, _ := proto.Marshal(reply)
			_ = writeFrame(conn, &frame{src: reply.MyPeerId, dst: request.src, kind: 2, version: 1, body: body})
			for {
				next, err := readFrame(conn)
				if err != nil {
					return
				}
				if next.kind == 4 && len(next.body) == 4 {
					_ = writeFrame(conn, &frame{src: reply.MyPeerId, dst: next.src, kind: 5, version: 1, body: next.body})
				}
			}
		}(conn)
	}
}

func core(listen, network, secret string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := corehost.New(ctx, corehost.Options{Platform: platform.Services{}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "host:", err)
		os.Exit(1)
	}
	defer host.Close(ctx)
	config, err := corehost.NewInstanceConfigBuilder(network).
		NetworkSecret(secret).
		Hostname("billow-t19-core").
		IPv4(netip.MustParsePrefix("10.144.0.1/24")).
		P2P(corehost.P2PPolicy{Disable: true}).
		Encryption(false).
		AddListeners("tcp://" + listen).
		Build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	instance, err := host.CreateInstance(ctx, config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "instance:", err)
		os.Exit(1)
	}
	defer instance.Close(ctx)
	if err := instance.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	port := 0
	if _, portText, err := net.SplitHostPort(listen); err == nil {
		fmt.Sscanf(portText, "%d", &port)
	}
	fmt.Printf("READY %d\n", port)
	time.Sleep(50 * time.Second)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	mode := flag.String("mode", "controlled", "controlled or core")
	network := flag.String("network", "billow-test", "network name")
	secret := flag.String("secret", "billow-secret", "network secret")
	reject := flag.Bool("reject", false, "reject the handshake")
	flag.Parse()
	if *mode == "core" {
		core(*listen, *network, *secret)
		return
	}
	controlled(*listen, *network, *secret, *reject)
}
