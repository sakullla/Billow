// SPDX-License-Identifier: GPL-3.0-only
//
// Sudoku table and codec differential vectors from the locked Mihomo source.
// Derived from Mihomo `transport/sudoku` (GPL-3.0).
// Upstream: https://github.com/MetaCubeX/mihomo
// Version: v1.19.34
// Commit: 0455d0d28c4526937380505153e65a843d8612e8
// Source paths: transport/sudoku/obfs/sudoku/* (table/codec API and
// `NewTableWithCustom`), transport/sudoku/init.go (`GenKeyPair`,
// `ClientAEADSeed`, `ServerAEADSeed`).
//
// The obfuscation table is a shuffle of the 288 4x4 grids derived from the key
// with Go's math/rand, so a Rust port is only wire-compatible when its table
// decodes the pinned encoder's bytes and its own bytes decode with the pinned
// table. This program exposes both directions of that comparison:
//
//	go run . -op vectors -key test-key-123 -mode prefer_entropy -plaintext 000102ff
//	go run . -op decode -key test-key-123 -mode prefer_entropy -wire <hex>
//	go run . -op decode-packed -key test-key-123 -mode prefer_entropy -wire <hex>
//
// This test-only generator links the GPL-3.0 pinned `transport/sudoku`; it is
// never linked into or distributed with the kernel.
//
// `vectors` prints the table hint, the padding pool, and the pinned pure and
// packed encodings of the fixture plaintext; `decode*` run the pinned decoder
// over wire bytes produced by the Rust port. The module is pinned through the
// replace directive to tool/kernel-compat/.cache/source/tree-v1.19.34.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku"
	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

// bufferConn is a net.Conn backed by buffers: writes are captured, reads come
// from the supplied bytes.
type bufferConn struct {
	out bytes.Buffer
	in  *bytes.Reader
}

func (c *bufferConn) Read(p []byte) (int, error) {
	if c.in == nil {
		return 0, io.EOF
	}
	return c.in.Read(p)
}
func (c *bufferConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *bufferConn) Close() error               { return nil }
func (c *bufferConn) LocalAddr() net.Addr        { return nil }
func (c *bufferConn) RemoteAddr() net.Addr       { return nil }
func (c *bufferConn) SetDeadline(time.Time) error {
	return nil
}
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

type vectors struct {
	Key         string `json:"key"`
	Mode        string `json:"mode"`
	Canonical   string `json:"canonical"`
	Hint        uint32 `json:"hint"`
	ASCII       bool   `json:"ascii"`
	PaddingPool string `json:"paddingPool"`
	Plaintext   string `json:"plaintext"`
	PureWire    string `json:"pureWire"`
	PackedWire  string `json:"packedWire"`
	// Salt separates runs so the Rust side sees fresh encoder choices.
	Salt string `json:"salt"`
}

func main() {
	op := flag.String("op", "vectors", "vectors | decode | decode-packed")
	key := flag.String("key", "test-key-123", "pre-shared key")
	mode := flag.String("mode", "prefer_entropy", "table-type")
	custom := flag.String("custom", "", "custom x/p/v pattern")
	plainHex := flag.String("plaintext", "0001020304050607ff", "plaintext to encode")
	wireHex := flag.String("wire", "", "wire bytes to decode")
	flag.Parse()

	table, err := sudoku.NewTableWithCustom(*key, *mode, *custom)
	if err != nil {
		fail("table: %v", err)
	}

	switch *op {
	case "vectors":
		plain, err := hex.DecodeString(*plainHex)
		if err != nil {
			fail("plaintext: %v", err)
		}
		out := vectors{
			Key:         *key,
			Mode:        *mode,
			Canonical:   canonical(*mode),
			Hint:        table.Hint(),
			ASCII:       table.IsASCII,
			PaddingPool: hex.EncodeToString(table.PaddingPool),
			Plaintext:   hex.EncodeToString(plain),
			Salt:        fmt.Sprintf("%d", time.Now().UnixNano()),
		}
		pure := &bufferConn{}
		pureConn := sudokuobfs.NewConn(pure, table, 0, 0, false)
		if _, err := pureConn.Write(plain); err != nil {
			fail("pure encode: %v", err)
		}
		out.PureWire = hex.EncodeToString(pure.out.Bytes())

		packed := &bufferConn{}
		packedConn := sudokuobfs.NewPackedConn(packed, table.OppositeDirection(), 0, 0)
		if _, err := packedConn.Write(plain); err != nil {
			fail("packed encode: %v", err)
		}
		if err := packedConn.Flush(); err != nil {
			fail("packed flush: %v", err)
		}
		out.PackedWire = hex.EncodeToString(packed.out.Bytes())

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fail("json: %v", err)
		}
	case "keypair":
		privateKey, publicKey, err := sudoku.GenKeyPair()
		if err != nil {
			fail("keypair: %v", err)
		}
		out := map[string]string{
			"privateKey":  privateKey,
			"publicKey":   publicKey,
			"clientSeed":  sudoku.ClientAEADSeed(privateKey),
			"serverSeed":  sudoku.ServerAEADSeed(publicKey),
			"publicSeed":  sudoku.ClientAEADSeed(publicKey),
			"publicCheck": sudoku.ServerAEADSeed(publicKey),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fail("json: %v", err)
		}
	case "decode", "decode-packed":
		wire, err := hex.DecodeString(*wireHex)
		if err != nil {
			fail("wire: %v", err)
		}
		conn := &bufferConn{in: bytes.NewReader(wire)}
		var reader io.Reader
		if *op == "decode" {
			reader = sudokuobfs.NewConn(conn, table, 0, 0, false)
		} else {
			reader = sudokuobfs.NewPackedConn(conn, table.OppositeDirection(), 0, 0)
		}
		plain, err := io.ReadAll(reader)
		if err != nil && !errors.Is(err, io.EOF) {
			fail("decode: %v", err)
		}
		fmt.Printf("{\"plaintext\":%q}\n", hex.EncodeToString(plain))
	default:
		fail("unknown op %q", *op)
	}
}

func canonical(mode string) string {
	parsed, err := sudokuobfs.ParseASCIIMode(mode)
	if err != nil {
		return ""
	}
	return parsed.Canonical()
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
