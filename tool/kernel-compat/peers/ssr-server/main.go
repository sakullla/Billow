// Independent SSR server for the Rust client tests.
//
// It uses the pinned Mihomo `shadowstream` cipher and the `protocol: origin` /
// `obfs: plain` framing: read the client IV, decrypt the SOCKS address, dial
// the target and relay both directions. This is deliberately not the Rust
// `SsrStream`; it is the server side of the wire format written against the
// locked Go implementation.
//
//	go run . -listen 127.0.0.1:0 -cipher aes-256-cfb -password ssr-pass
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowstream"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "listen address")
	cipherName := flag.String("cipher", "aes-256-cfb", "SSR cipher")
	password := flag.String("password", "", "SSR password")
	flag.Parse()

	ciph, err := core.PickCipher(*cipherName, nil, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipher: %v\n", err)
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("READY %s\n", ln.Addr().String())
	os.Stdout.Sync()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(raw, ciph, *cipherName)
	}
}

func handle(raw net.Conn, ciph core.Cipher, cipherName string) {
	defer raw.Close()
	var conn net.Conn = raw
	if cipherName != "dummy" && cipherName != "none" {
		stream, ok := ciph.(*core.StreamCipher)
		if !ok {
			return
		}
		conn = shadowstream.NewConn(raw, stream.Cipher)
	}
	target, err := readSocksAddr(conn)
	if err != nil {
		return
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, conn)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(conn, upstream)
	<-done
}

func readSocksAddr(r io.Reader) (string, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", err
	}
	var host string
	switch kind[0] {
	case 0x01:
		var addr [4]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", err
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	case 0x04:
		var addr [16]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	default:
		return "", fmt.Errorf("unknown address type %d", kind[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(port[:]))), nil
}
