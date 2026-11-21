// Pinned gost relay dialer harness.
//
// `tool/kernel-compat/peers/ssr-plugins` is the controlled *server*; this
// program is the client side built from the locked tree itself:
// `transport/gost.NewRelayDialer` (the same code Mihomo's `gost-relay` outbound
// uses) drives the controlled relay peer in
// `native-kernel/crates/billow-kernel/tests/protocols.rs`. That closes the
// "both sides are our own implementation" gap for the UDP association and the
// smux session: the Rust client and the pinned dialer must both be accepted by
// the same server.
//
//	go run . -relay 127.0.0.1:9000 -target 127.0.0.1:7 -mux -mode tcp
//	go run . -relay 127.0.0.1:9000 -target 127.0.0.1:9 -mux -mode udp
//
// It prints `OK tcp` / `OK udp` on success and exits non-zero on failure.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gost"
)

// directDialer is the base dialer the pinned relay dialer wraps. The relay
// dialer only ever calls DialContext for the relay server itself (the UDP
// association is carried inside that TCP connection), so ListenPacket is
// unreachable but required by the interface.
type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (directDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	var listen net.ListenConfig
	return listen.ListenPacket(ctx, network, address)
}

var _ C.Dialer = directDialer{}

func main() {
	relay := flag.String("relay", "", "relay server host:port")
	target := flag.String("target", "", "target host:port")
	mux := flag.Bool("mux", false, "enable the smux session")
	mode := flag.String("mode", "tcp", "tcp, udp or both")
	marker := flag.String("marker", "gost-harness", "payload to send")
	flag.Parse()

	if *relay == "" || *target == "" {
		fail("both -relay and -target are required")
	}
	host, portText, err := net.SplitHostPort(*relay)
	if err != nil {
		fail("relay address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		fail("relay port: %v", err)
	}
	dialer := gost.NewRelayDialer(directDialer{}, &gost.RelayOption{
		Server: host,
		Port:   port,
		Mux:    *mux,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if *mode == "tcp" || *mode == "both" {
		conn, err := dialer.DialContext(ctx, "tcp", *target)
		if err != nil {
			fail("tcp dial: %v", err)
		}
		back, err := roundtrip(conn, []byte(*marker))
		_ = conn.Close()
		if err != nil {
			fail("tcp relay: %v", err)
		}
		if string(back) != *marker {
			fail("tcp echo mismatch: got %q want %q", back, *marker)
		}
		fmt.Println("OK tcp")
	}

	if *mode == "udp" || *mode == "both" {
		rAddrPort, err := netip.ParseAddrPort(*target)
		if err != nil {
			fail("udp target must be an ip:port: %v", err)
		}
		pc, err := dialer.ListenPacket(ctx, "udp", "", rAddrPort)
		if err != nil {
			fail("udp association: %v", err)
		}
		defer pc.Close()
		if _, err := pc.WriteTo([]byte(*marker), net.UDPAddrFromAddrPort(rAddrPort)); err != nil {
			fail("udp write: %v", err)
		}
		buf := make([]byte, 65535)
		read, _, err := pc.ReadFrom(buf)
		if err != nil {
			fail("udp read: %v", err)
		}
		if string(buf[:read]) != *marker {
			fail("udp echo mismatch: got %q want %q", buf[:read], *marker)
		}
		fmt.Println("OK udp")
	}
}

func roundtrip(conn net.Conn, marker []byte) ([]byte, error) {
	if _, err := conn.Write(marker); err != nil {
		return nil, err
	}
	back := make([]byte, len(marker))
	if _, err := io.ReadFull(conn, back); err != nil {
		return nil, err
	}
	return back, nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
