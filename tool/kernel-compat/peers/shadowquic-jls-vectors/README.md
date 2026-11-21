# ShadowQUIC JLS vector generator

Builds real JLS ClientHello/ServerHello messages with the pinned
`github.com/metacubex/jls-tls` module and prints them as the text fixture
`native-kernel/crates/billow-kernel/tests/data/shadowquic-jls.txt`. The Rust
kernel's `src/outbound/jls.rs` opens those messages, which cross-checks the
AES-256-GCM key/nonce/32-byte-nonce construction against the locked Go
package rather than only against itself.

Run offline (the module cache must already contain `jls-tls` and its
transitive modules):

```sh
cd tool/kernel-compat/peers/shadowquic-jls-vectors
GOFLAGS=-mod=mod GOPROXY=off go run . \
  > ../../../../native-kernel/crates/billow-kernel/tests/data/shadowquic-jls.txt
```

The output starts with `#` comment lines; the Rust fixture parser ignores
lines without `=`.

`jls-tls` is BSD-3-Clause (Copyright 2009 The Go Authors); the full license is
in `LICENSE` here and in `native-kernel/THIRD_PARTY_NOTICES.md`. The generator
is a test tool only; no Go code is linked into the kernel.
