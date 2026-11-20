// Package mihomoios embeds the pinned MetaCubeX/mihomo v1.19.34 build
// (commit 0455d0d28c4526937380505153e65a843d8612e8, build tags with_gvisor,cmfa)
// as an iOS Go archive and drives it from the Billow Mihomo Packet Tunnel
// extension.
//
// Data path (public mihomo / sing-tun APIs only):
//
//	NEPacketTunnelProvider.packetFlow IP packets
//	  -> Swift pump: packetFlow.readPackets (Swift owns struct lifetimes)
//	  -> GoMihomoReadPacket (C export): one IP packet per call, injected into
//	     the gVisor stack
//	  (switching the poll to the notification-socket API is tracked for T7)
//	  -> sing-tun gVisor stack LinkEndpoint
//	       |-> TCP/UDP/ICMP -> mihomo tunnel.HandleTCPConn / HandleUDPPacket
//	       |    (rules, DNS hijack of :53 goes to the configured DNS, proxies)
//	       +-> egress -> stack writes -> packetEndpoint.WritePackets
//	            -> GoMihomoWritePackets (C export) -> port.write
//	            -> packetFlow.writePackets (blocks until consumed)
//
// Callback direction Go -> Swift: Swift passes @convention(c) function
// pointers (its write / network-check port functions) and the opaque provider
// context to GoMihomoStart; Go calls them through the C helper of the preamble.
// Swift -> Go uses the //export functions below. No Go function address is
// handed to Swift.
//
// Package main: -buildmode=c-archive needs a main package. main() never runs
// (the extension calls the exports); Swift declares them with @_silgen_name
// through billow_mihomo_bridge.h.
//
// Source mapping (upstream files relative to the module root; resolve it with
// `go list -m -f '{{.Dir}}' github.com/metacubex/mihomo`):
//
//	hub/executor/executor.go:64     Parse (default path)
//	hub/executor/executor.go:79     ParseWithBytes (initial load and reload)
//	hub/executor/executor.go:85     ApplyConfig
//	hub/executor/executor.go:532    Shutdown
//	config/initial.go:12            config.Init (home dir, default config.yaml)
//	constant/path.go:62             C.SetHomeDir
//	tunnel/tunnel.go:80             Tunnel.HandleTCPConn
//	tunnel/tunnel.go:99             Tunnel.HandleUDPPacket
//	listener/sing_tun/server.go:136 sing_tun.New(options LC.Tun, tunnel C.Tunnel)
//	listener/sing_tun/server.go:152 fd==0 would open a utun socket (not used)
//	listener/sing_tun/server.go:489 tun.NewStack(options.Stack) -> gVisor
//	listener/sing_tun/server.go:605 OnReload
//	listener/sing_tun/server.go:677 Close (tunStack, tunIf, monitors, ...)
//	listener/sing_tun/server.go:701 Address
//	listener/sing_tun/dns.go:21     ShouldHijackDns
//	listener/sing_tun/prepare.go:18 PrepareConnection
//	listener/sing/sing.go:126       NewConnection -> tunnel.HandleTCPConn
//	listener/sing/sing.go:215       NewPacket -> tunnel.HandleUDPPacket
//	listener/config/tun.go:19       LC.Tun
//	tunnel/mode.go:256             tunnel.SetMode (TUN readers inherit the config mode)
//
// Upstream v1.19.34 has no cgo //export entry point (no embedded package) and
// no packetFlow-backed GVisorTun: sing-tun only ships one for file descriptors
// (internal/fdbased_darwin). gVisorTun and packetEndpoint below implement the
// public interfaces instead:
//
//	sing-tun tun.go:44           Tun (io.ReadWriter, Close)
//	sing-tun tun.go:66           GVisorTun (WritePacket, NewEndpoint)
//	sing-tun stack_gvisor.go:85  GVisor.Start
//	sing-tun stack_gvisor.go:105 GVisor.Close (endpoint.Attach(nil), CleanupEndpoints)
//	gvisor registration.go       LinkEndpoint (NetworkLinkEndpoint + LinkWriter)
//
// LC.Tun.FileDescriptor is a non-zero sentinel so sing-tun neither opens a utun
// socket nor touches the system resolver (tunNew is then unused).
package main

/*
#include <stdint.h>
#include <stdlib.h>

__attribute__((unused)) static int64_t billowMihomoCallWrite(uintptr_t fn, void *ctx, void *packet, uint32_t length) {
	return ((int64_t (*)(void *, void *, uint32_t))fn)(ctx, packet, length);
}

__attribute__((unused)) static int64_t billowMihomoCallCheck(uintptr_t fn, void *ctx) {
	return ((int64_t (*)(void *))fn)(ctx);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/config"
	Cst "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/tunnel"
	singtun "github.com/metacubex/sing-tun"
)

// version is the mihomo release injected with -ldflags at link time.
var version = "devel"

const (
	mtu          = 9000
	fdSentinel   = 1 // non-zero: keep sing-tun away from utun and DNS registration
	tunName      = "utun-billow"
	dnsHijack    = "any:53"
	inet4Address = "198.18.0.1/16"
	inet6Address = "fdfe:dcba:9876::1/126"
)

type instance struct {
	tunnel *sing_tun.Listener
	gTun   *gVisorTun

	closeOnce sync.Once
	closed    chan struct{}

	readMu sync.Mutex
}

func (in *instance) close() error {
	var err error
	in.closeOnce.Do(func() {
		if in.tunnel != nil {
			err = in.tunnel.Close()
		}
		close(in.closed)
	})
	return err
}

func newInstance() (*instance, error) {
	in := &instance{closed: make(chan struct{})}
	in.gTun = &gVisorTun{in: in}
	options := LC.Tun{
		Enable:              true,
		Device:              tunName,
		FileDescriptor:      fdSentinel,
		Stack:               Cst.TunGvisor,
		MTU:                 mtu,
		AutoRoute:           false,
		AutoDetectInterface: false,
		DNSHijack:           []string{dnsHijack},
		Inet4Address:        []netip.Prefix{netip.MustParsePrefix(inet4Address)},
		Inet6Address:        []netip.Prefix{netip.MustParsePrefix(inet6Address)},
	}
	l, err := sing_tun.New(options, tunnel.Tunnel)
	if err != nil {
		return nil, fmt.Errorf("sing_tun.New: %w", err)
	}
	in.tunnel = l
	return in, nil
}

func loadConfig() error {
	path := Cst.Path.Config()
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	cfg, err := executor.ParseWithBytes(data)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	executor.ApplyConfig(cfg, true)
	return nil
}

func fail(errOut **C.char, format string, args ...any) C.int {
	if errOut != nil {
		*errOut = C.CString(fmt.Sprintf(format, args...))
		return -1
	}
	return -3
}

var (
	currentMu sync.Mutex
	current   *instance
)

func getCurrent() *instance {
	currentMu.Lock()
	defer currentMu.Unlock()
	return current
}

// GoMihomoStart installs the Swift packet port (ctx is the opaque
// NEPacketTunnelProvider pointer), loads config.yaml from home (geo, rule and
// mmdb assets are installed by the host beforehand) and starts the gVisor
// stack. Returns 0 on success; otherwise *errOut holds a malloc'd message the
// caller must free.
//
//export GoMihomoStart
func GoMihomoStart(home *C.char, writeCB C.uintptr_t, checkNetworkCB C.uintptr_t, userCtx unsafe.Pointer, errOut **C.char) (rc C.int) {
	currentMu.Lock()
	defer currentMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			if current != nil {
				current.close()
				current = nil
			}
			rc = fail(errOut, "mihomo: panic: %v", r)
		}
	}()
	if current != nil {
		current.close()
		current = nil
	}
	if home == nil {
		return fail(errOut, "mihomo: empty home directory")
	}
	dir := C.GoString(home)
	if dir == "" {
		return fail(errOut, "mihomo: empty home directory")
	}
	if writeCB == 0 {
		return fail(errOut, "mihomo: missing write callback")
	}
	Cst.SetHomeDir(dir)
	if err := config.Init(dir); err != nil {
		return fail(errOut, "mihomo: %v", err)
	}
	if err := loadConfig(); err != nil {
		return fail(errOut, "mihomo: %v", err)
	}
	registerCallbacks(writeCB, checkNetworkCB, userCtx)
	in, err := newInstance()
	if err != nil {
		writePort.Store(nil)
		networkCheck.Store(nil)
		portCtx.Store(nil)
		return fail(errOut, "mihomo: %v", err)
	}
	current = in
	if in.tunnel != nil {
		log.Infoln("[iOS] mihomo %s embedded, home=%s tun=%s", version, dir, in.tunnel.Address())
	} else {
		log.Infoln("[iOS] mihomo %s embedded, home=%s", version, dir)
	}
	return 0
}

// GoMihomoVersion writes the embedded mihomo version into buf as a C string.
//
//export GoMihomoVersion
func GoMihomoVersion(buf *C.char, size C.int) C.int {
	if buf == nil || size <= 0 {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(size))
	n := copy(dst[:size-1], version)
	dst[n] = 0
	return C.int(n)
}

// GoMihomoReload re-parses config.yaml while keeping the stack (routes, TUN
// addresses and hijack rules stay in place); a failing parse keeps the old
// configuration.
//
//export GoMihomoReload
func GoMihomoReload(errOut **C.char) (rc C.int) {
	currentMu.Lock()
	defer currentMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			rc = fail(errOut, "mihomo: panic: %v", r)
		}
	}()
	if current == nil {
		return fail(errOut, "mihomo: not running")
	}
	if err := loadConfig(); err != nil {
		return fail(errOut, "mihomo: %v", err)
	}
	current.tunnel.OnReload()
	return 0
}

// GoMihomoNetworkChanged lets the extension report a path change. The engine
// answers 0 when the gVisor stack still routes (mihomo dials every proxy
// through the system default interface, which iOS re-selects after a Wi-Fi /
// cellular switch) and non-zero when the extension must restart the tunnel.
//
//export GoMihomoNetworkChanged
func GoMihomoNetworkChanged() C.int {
	in := getCurrent()
	if in == nil {
		return 1
	}
	fn := networkCheck.Load()
	if fn == nil {
		return 0
	}
	ctx := portCtx.Load()
	if ctx == nil {
		return 1
	}
	return C.int((*fn)(*ctx))
}

// GoMihomoShutdown stops the stack and shuts down the embedded executor.
//
//export GoMihomoShutdown
func GoMihomoShutdown() {
	currentMu.Lock()
	defer currentMu.Unlock()
	in := current
	current = nil
	if in != nil {
		if err := in.close(); err != nil {
			log.Warnln("[iOS] close mihomo tun: %v", err)
		}
	}
	executor.Shutdown()
}

// GoMihomoReadPacket decodes one IP packet from Swift's packed
// [4-byte big-endian length][IP packet] record, injects it into the gVisor
// stack and returns the packet length, 0 when the record is malformed, or -1
// when no engine runs. Swift owns the readPackets pump; Go never holds
// NEPacketTunnelFlow structs.
//
//export GoMihomoReadPacket
func GoMihomoReadPacket(record unsafe.Pointer, size C.uint32_t) C.int {
	in := getCurrent()
	if in == nil {
		return -1
	}
	buf := unsafe.Slice((*byte)(record), int(size))
	if len(buf) < 4 {
		return 0
	}
	n := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if n < 20 || 4+n > len(buf) {
		return 0
	}
	if err := in.gTun.deliver(buf[4 : 4+n]); err != nil {
		log.Debugln("[iOS] drop inbound packet: %v", err)
		return 0
	}
	return C.int(n)
}

// GoMihomoWritePackets is called for every egress packet produced by the
// stack; returns 0 on success.
//
//export GoMihomoWritePackets
func GoMihomoWritePackets(packet unsafe.Pointer, length C.uint32_t) C.int {
	return C.int(writePacket(packet, uint32(length)))
}

// Callback state registered by the extension before GoMihomoStart.
var (
	writePort    atomic.Pointer[func(ctx unsafe.Pointer, packet unsafe.Pointer, length C.uint32_t) C.int64_t]
	networkCheck atomic.Pointer[func(ctx unsafe.Pointer) C.int64_t]
	portCtx      atomic.Pointer[unsafe.Pointer]
)

// registerCallbacks stores the Swift port functions (passed to GoMihomoStart
// by the extension) and the opaque NEPacketTunnelProvider context.
func registerCallbacks(writeCB, checkCB C.uintptr_t, ctx unsafe.Pointer) {
	w := func(ctx unsafe.Pointer, packet unsafe.Pointer, length C.uint32_t) C.int64_t {
		return C.billowMihomoCallWrite(writeCB, ctx, packet, length)
	}
	writePort.Store(&w)
	c := func(ctx unsafe.Pointer) C.int64_t {
		if checkCB == 0 {
			return 0
		}
		return C.billowMihomoCallCheck(checkCB, ctx)
	}
	networkCheck.Store(&c)
	portCtx.Store(&ctx)
}

func writePacket(packet unsafe.Pointer, length uint32) int {
	if length == 0 {
		return 0
	}
	fn := writePort.Load()
	ctxp := portCtx.Load()
	if fn == nil || ctxp == nil {
		return -1
	}
	if (*fn)(*ctxp, packet, C.uint32_t(length)) != 0 {
		return -1
	}
	return 0
}

// loopback carries TCP/UDP from a network the packet tunnel does not carry
// (T7 Rust data plane on its own tun). Accepted connections and packets enter
// the same mihomo tunnel as packetFlow traffic, so DNS hijack and rules are
// shared; connections are selected statistically by fraction.
var loopback = struct {
	mu       sync.Mutex
	listener net.Listener
	udp      *net.UDPConn
	addr     string
	fraction float64
	seq      atomic.Uint64
}{fraction: 1}

// GoMihomoLoopbackStart listens on addr ("host:port", port 0 picks one) for a
// fraction (0..1) of new connections and packets. An empty addr does nothing.
// Returns the bound port or -1.
//
//export GoMihomoLoopbackStart
func GoMihomoLoopbackStart(addr *C.char, fraction C.double) C.int {
	bind := C.GoString(addr)
	loopback.mu.Lock()
	if loopback.listener != nil {
		loopback.mu.Unlock()
		return -1
	}
	if bind == "" {
		loopback.mu.Unlock()
		return 0
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		loopback.mu.Unlock()
		log.Warnln("[iOS] loopback tcp listen %s: %v", bind, err)
		return -1
	}
	ua, err := net.ResolveUDPAddr("udp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		loopback.mu.Unlock()
		return -1
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		_ = ln.Close()
		loopback.mu.Unlock()
		log.Warnln("[iOS] loopback udp listen: %v", err)
		return -1
	}
	loopback.listener, loopback.udp = ln, pc
	loopback.addr = ln.Addr().String()
	loopback.fraction = float64(fraction)
	bound := C.int(ln.Addr().(*net.TCPAddr).Port)
	loopback.mu.Unlock()
	go acceptLoop(ln)
	go serveLoopUDP(pc)
	log.Infoln("[iOS] loopback listening on %s", ln.Addr())
	return bound
}

// GoMihomoLoopbackStop closes the loopback listeners; open connections finish.
//
//export GoMihomoLoopbackStop
func GoMihomoLoopbackStop() {
	loopback.mu.Lock()
	ln, pc := loopback.listener, loopback.udp
	loopback.listener, loopback.udp, loopback.addr = nil, nil, ""
	loopback.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}
}

func loopbackSelected() bool {
	loopback.mu.Lock()
	f := loopback.fraction
	loopback.mu.Unlock()
	return f >= 1 || float64(loopback.seq.Add(1)%1000) < f*1000
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !loopbackSelected() {
			_ = conn.Close()
			continue
		}
		go handleLoopConn(conn)
	}
}

// handleLoopConn forwards a loopback TCP connection into the tunnel with the
// original peer address as inbound source so rules see it.
func handleLoopConn(conn net.Conn) {
	tunnel.Tunnel.HandleTCPConn(inbound.NewSocket(socks5.ParseAddr(conn.RemoteAddr().String()), conn, Cst.TUN))
}

func serveLoopUDP(pc *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !loopbackSelected() {
			continue
		}
		local := *pc.LocalAddr().(*net.UDPAddr)
		localIP, _ := netip.AddrFromSlice(local.IP)
		srcIP, _ := netip.AddrFromSlice(src.IP)
		tunnel.Tunnel.HandleUDPPacket(loopUDPPacket{
			payload: append([]byte(nil), buf[:n]...),
			src:     *src,
			local:   local,
			pc:      pc,
		}, &Cst.Metadata{
			NetWork: Cst.UDP,
			Type:    Cst.TUN,
			SrcIP:   srcIP.Unmap(),
			SrcPort: uint16(src.Port),
			DstIP:   localIP.Unmap(),
			DstPort: uint16(local.Port),
		})
	}
}

// loopUDPPacket implements Cst.PacketAdapter for loopback datagrams; WriteBack
// sends the reply from the loopback socket to the original peer.
type loopUDPPacket struct {
	payload []byte
	src     net.UDPAddr
	local   net.UDPAddr
	pc      *net.UDPConn
}

func (p loopUDPPacket) Data() []byte { return p.payload }

func (p loopUDPPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	dst := net.Addr(&p.src)
	if addr != nil {
		dst = addr
	}
	return p.pc.WriteToUDP(b, dst.(*net.UDPAddr))
}

func (p loopUDPPacket) Drop() {}

func (p loopUDPPacket) LocalAddr() net.Addr { return &p.local }

func (p loopUDPPacket) Metadata() *Cst.Metadata {
	srcIP, _ := netip.AddrFromSlice(p.src.IP)
	localIP, _ := netip.AddrFromSlice(p.local.IP)
	return &Cst.Metadata{
		NetWork: Cst.UDP,
		Type:    Cst.TUN,
		SrcIP:   srcIP.Unmap(),
		SrcPort: uint16(p.src.Port),
		DstIP:   localIP.Unmap(),
		DstPort: uint16(p.local.Port),
	}
}

func (p loopUDPPacket) Key() string {
	ip, _ := netip.AddrFromSlice(p.src.IP)
	return netip.AddrPortFrom(ip.Unmap(), uint16(p.src.Port)).String()
}

var _ Cst.PacketAdapter = loopUDPPacket{}

// gVisorTun implements singtun.GVisorTun on the Swift packet port.
type gVisorTun struct {
	in *instance

	mu   sync.RWMutex
	disp stack.NetworkDispatcher
}

func (t *gVisorTun) Read([]byte) (int, error) {
	// Egress goes through the endpoint, not io.Reader. Block until shutdown so
	// any stack goroutine that calls Read does not spin.
	<-t.in.closed
	return 0, errors.New("mihomo: gVisorTun closed")
}

func (t *gVisorTun) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if writePacket(unsafe.Pointer(&p[0]), uint32(len(p))) != 0 {
		return 0, errors.New("packetFlow.writePackets failed")
	}
	return len(p), nil
}

func (t *gVisorTun) Close() error {
	t.mu.Lock()
	t.disp = nil
	t.mu.Unlock()
	return nil
}

func (t *gVisorTun) deliver(packet []byte) error {
	t.mu.RLock()
	d := t.disp
	t.mu.RUnlock()
	if d == nil {
		return errors.New("stack not attached")
	}
	if len(packet) < 20 {
		return errors.New("short packet")
	}
	var proto tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return errors.New("not an IP packet")
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	d.DeliverNetworkPacket(proto, pkt)
	pkt.DecRef()
	return nil
}

func (t *gVisorTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	view := pkt.ToView()
	defer view.Release()
	data := view.AsSlice()
	if len(data) == 0 {
		return 0, nil
	}
	if writePacket(unsafe.Pointer(&data[0]), uint32(len(data))) != 0 {
		return 0, errors.New("packetFlow.writePackets failed")
	}
	return len(data), nil
}

func (t *gVisorTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return &packetEndpoint{tun: t}, stack.NICOptions{}, nil
}

// packetEndpoint is a headerless gVisor LinkEndpoint bridged to packetFlow.
type packetEndpoint struct {
	tun  *gVisorTun
	mu   sync.RWMutex
	disp stack.NetworkDispatcher
	mtu  uint32
}

func (e *packetEndpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	e.disp = d
	e.mu.Unlock()
	e.tun.mu.Lock()
	e.tun.disp = d
	e.tun.mu.Unlock()
}

func (e *packetEndpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.disp != nil
}

func (e *packetEndpoint) MTU() uint32 {
	if e.mtu == 0 {
		return mtu
	}
	return e.mtu
}

func (e *packetEndpoint) SetMTU(m uint32) { e.mtu = m }

func (e *packetEndpoint) MaxHeaderLength() uint16 { return 0 }

func (e *packetEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

func (e *packetEndpoint) SetLinkAddress(tcpip.LinkAddress) {}

func (e *packetEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }

func (e *packetEndpoint) SetOnCloseAction(func()) {}

func (e *packetEndpoint) Wait() {}

func (e *packetEndpoint) Close() {
	e.mu.Lock()
	e.disp = nil
	e.mu.Unlock()
	e.tun.mu.Lock()
	e.tun.disp = nil
	e.tun.mu.Unlock()
}

func (e *packetEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader/ParseHeader: headerless endpoint, the IP header stays in the buffer.
func (e *packetEndpoint) AddHeader(*stack.PacketBuffer) {}

func (e *packetEndpoint) ParseHeader(*stack.PacketBuffer) bool { return false }

func (e *packetEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if _, err := e.tun.WritePacket(pkt); err != nil {
			return n, &tcpip.ErrClosedForSend{}
		}
		n++
	}
	return n, nil
}

var (
	_ singtun.Tun        = (*gVisorTun)(nil)
	_ singtun.GVisorTun  = (*gVisorTun)(nil)
	_ stack.LinkEndpoint = (*packetEndpoint)(nil)
)

// main exists only because -buildmode=c-archive requires a main package;
// the extension calls the //export functions instead.
func main() {}
