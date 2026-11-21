// Prints the pinned SSR stream-cipher keystream vectors used by the Rust unit
// tests. Build/run: `go run .` in this directory (the replace directive points
// at the locked source tree under tool/kernel-compat/.cache/source).
package main

import (
	"fmt"

	"github.com/metacubex/mihomo/transport/shadowsocks/core"
)

func main() {
	const password = "ssr-test-password"
	plain := []byte("ssr-cipher-vector")
	for _, name := range []string{
		"AES-128-CFB", "AES-192-CFB", "AES-256-CFB",
		"AES-128-CTR", "AES-192-CTR", "AES-256-CTR",
		"RC4-MD5", "CHACHA20", "CHACHA20-IETF", "XCHACHA20",
	} {
		ciph, err := core.PickCipher(name, nil, password)
		if err != nil {
			panic(err)
		}
		stream := ciph.(*core.StreamCipher)
		iv := []byte("0123456789abcdef01234567")[:stream.IVSize()]
		data := append([]byte(nil), plain...)
		stream.Encrypter(iv).XORKeyStream(data, data)
		fmt.Printf("%-14s iv=%x cipher=%x\n", name, iv, data)
	}
}
