// Controlled Tailscale peer for T19: the control mode runs the locked
// `controlbase.Server` behind the ts2021 HTTP upgrade and an HTTP/2 server;
// the DERP mode implements the public DERP greeting/client-info/ping frames
// and checks the NaCl-boxed client info.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/metacubex/tailscale/control/controlbase"
	tskey "github.com/metacubex/tailscale/types/key"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/http2"
)

const derpMagic = "DERP\xf0\x9f\x94\x91"

func readHTTPHead(reader *bufio.Reader) (string, map[string]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	headers := map[string]string{}
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		for i := 0; i < len(line); i++ {
			if line[i] == ':' {
				key := line[:i]
				value := line[i+1:]
				for len(value) > 0 && (value[0] == ' ' || value[0] == '\t') {
					value = value[1:]
				}
				for len(value) > 0 && (value[len(value)-1] == '\r' || value[len(value)-1] == '\n') {
					value = value[:len(value)-1]
				}
				headers[key] = value
				break
			}
		}
	}
	return line, headers, nil
}

func control(listen string) {
	key := tskey.NewMachine()
	public := key.Public()
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("READY %d %s\n", listener.Addr().(*net.TCPAddr).Port, hex.EncodeToString(public.UntypedBytes()))
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			reader := bufio.NewReader(conn)
			_, headers, err := readHTTPHead(reader)
			if err != nil {
				fmt.Fprintln(os.Stderr, "http head:", err)
				return
			}
			init, err := base64.StdEncoding.DecodeString(headers["X-Tailscale-Handshake"])
			if err != nil {
				fmt.Fprintln(os.Stderr, "handshake header:", err, headers)
				return
			}
			if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n"); err != nil {
				return
			}
			if reader.Buffered() > 0 {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cb, err := controlbase.Server(ctx, conn, key, init)
			if err != nil {
				fmt.Fprintln(os.Stderr, "controlbase:", err)
				return
			}
			fmt.Fprintln(os.Stderr, "controlbase ok")
			server := &http2.Server{}
			server.ServeConn(cb, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					if r.URL.Path != "/machine/map" {
						http.NotFound(w, r)
						return
					}
					var request map[string]any
					_ = json.Unmarshal(body, &request)
					w.Header().Set("content-type", "application/json")
					_, _ = w.Write([]byte("{\"Node\":{\"Name\":\"t19\"},\"Peers\":[]}\n"))
				}),
			})
		}(conn)
	}
}

func writeFrame(conn net.Conn, kind byte, body []byte) error {
	header := make([]byte, 5)
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(body)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

func readFrame(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length > 1<<20 {
		return 0, nil, fmt.Errorf("frame too large")
	}
	body := make([]byte, length)
	_, err := io.ReadFull(conn, body)
	return header[0], body, err
}

func derp(listen string) {
	serverPublic, serverPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("READY %d %s\n", listener.Addr().(*net.TCPAddr).Port, hex.EncodeToString(serverPublic[:]))
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			reader := bufio.NewReader(conn)
			if _, _, err := readHTTPHead(reader); err != nil {
				return
			}
			if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: upgrade\r\n\r\n"); err != nil {
				return
			}
			body := append([]byte(derpMagic), serverPublic[:]...)
			body = append(body, []byte("{}")...)
			if err := writeFrame(conn, 0x01, body); err != nil {
				return
			}
			kind, clientInfo, err := readFrame(conn)
			if err != nil || kind != 0x02 || len(clientInfo) < 32+24+16 {
				return
			}
			var clientPublic [32]byte
			copy(clientPublic[:], clientInfo[:32])
			var nonce [24]byte
			copy(nonce[:], clientInfo[32:56])
			cleartext, ok := box.Open(nil, clientInfo[56:], &nonce, &clientPublic, serverPrivate)
			if !ok {
				return
			}
			var info map[string]any
			if json.Unmarshal(cleartext, &info) != nil {
				return
			}
			for {
				kind, body, err := readFrame(conn)
				if err != nil {
					return
				}
				switch kind {
				case 0x12: // ping
					_ = writeFrame(conn, 0x13, body)
				case 0x04: // send packet -> echo as recv packet
					if len(body) >= 32 {
						reply := append([]byte{}, body[32:]...)
						_ = writeFrame(conn, 0x05, reply)
					}
				}
			}
		}(conn)
	}
}

func main() {
	mode := flag.String("mode", "control", "control or derp")
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	flag.Parse()
	if *mode == "derp" {
		derp(*listen)
		return
	}
	control(*listen)
}
