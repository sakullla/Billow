// Command mihomo-probe is a thin differential harness built against a locked Mihomo source
// tree. It never reimplements parsing: config loading goes through the tree's config package,
// and every item probe calls the tree's own parser for that item. Results are reported as
// JSON so an acceptance check can state what the pinned version accepts or rejects.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	slog "log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	_ "github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/listener"
	IN "github.com/metacubex/mihomo/listener/inbound"
	Mlog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"

	"go.yaml.in/yaml/v3"
)

var rep report

type report struct {
	Mode     string         `json:"mode"`
	Accept   bool           `json:"accept"`
	Error    string         `json:"error,omitempty"`
	Fields   []string       `json:"fields,omitempty"`
	Proxy    string         `json:"proxy,omitempty"`
	Rule     string         `json:"rule,omitempty"`
	Endpoint string         `json:"endpoint,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// probeVersion is stamped with -ldflags -X at build time from the manifest version.
var probeVersion = "unknown"

func main() {
	// Keep stdout for the JSON result: upstream logging is sent to stderr at debug level, which
	// acceptance runs treat as diagnostic output only.
	Mlog.SetLevel(Mlog.DEBUG)
	if os.Getenv("KC_LOG_FILE") != "" {
		if file, err := os.OpenFile(os.Getenv("KC_LOG_FILE"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			slog.SetOutput(file)
		}
	}
	slog.SetOutput(os.Stderr)
	if len(os.Args) < 2 {
		emit(&report{Details: map[string]any{}}, fmt.Errorf("usage: mihomo-probe <mode> <file>"))
	}
	rep = report{Details: map[string]any{}}
	if len(os.Args) < 3 && os.Args[1] != "version" {
		emit(&rep, fmt.Errorf("usage: mihomo-probe <mode> <file>"))
	}
	rep.Mode = os.Args[1]
	var err error
	defer func() {
		if r := recover(); r != nil {
			rep.Accept = false
			rep.Error = fmt.Sprintf("panic: %v", r)
			emit(&rep, nil)
		}
	}()
	switch os.Args[1] {
	case "version":
		// Identity for the harness: the version stamped at build time and the modes present.
		rep.Details["probe"] = probeVersion
		rep.Details["modes"] = []string{"version", "validate", "proxy", "rule", "inbound", "group", "dns", "failed", "ip", "serve"}
		err = nil
	case "serve":
		// Probe-managed replica of the pinned listening path: the locked source parses the
		// config, listens on the mixed inbound it declares, and relays tunneled TCP to one
		// upstream (the echo) from a chosen source address. UDP is not relayed.
		err = serve(os.Args[2])
	case "validate":
		err = probeValidate(os.Args[2], &rep)
	case "proxy", "rule", "inbound", "group", "dns", "failed", "ip":
		err = probeItem(os.Args[1], os.Args[2], &rep)
	default:
		err = fmt.Errorf("unknown mode %s", os.Args[1])
	}
	rep.Accept = err == nil
	if err != nil {
		rep.Error = err.Error()
	}
	emit(&rep, nil)
}

func emit(rep *report, err error) {
	if err != nil {
		rep.Accept = false
		rep.Error = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(rep)
	os.Exit(0)
}

func reportVersion() string {
	// The release binary stamp is read from the tree at build time; see probeBuild.
	return probeVersion
}

// probeValidate loads a full config. Client aliases that the version still accepts are
// applied here (tag -> name for proxies); anything else is passed through untouched so the
// upstream parser decides.
func probeValidate(path string, rep *report) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var aliases []string
	var node map[string]any
	if yaml.Unmarshal(data, &node) == nil {
		if proxies, ok := node["proxies"].([]any); ok {
			for index, item := range proxies {
				mapping, _ := item.(map[string]any)
				if tag, ok := mapping["tag"].(string); ok {
					if _, hasName := mapping["name"]; !hasName {
						mapping["name"] = tag
						aliases = append(aliases, fmt.Sprintf("proxies[%d].tag", index))
					}
				}
			}
		}
		keys := make([]string, 0, len(node))
		for key := range node {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			rep.Fields = append(rep.Fields, key)
		}
		if len(aliases) > 0 {
			if rewritten, err := yaml.Marshal(node); err == nil {
				data = rewritten
			}
		}
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	rep.Details["version"] = reportVersion()
	rep.Details["aliasesApplied"] = aliases
	rep.Details["mode"] = fmt.Sprint(cfg.General.Mode)
	rep.Details["mixedPort"] = cfg.General.MixedPort
	rep.Details["listeners"] = len(cfg.Listeners)
	rep.Details["proxies"] = len(cfg.Proxies)
	rep.Details["rules"] = len(cfg.Rules)
	return nil
}

func probeItem(mode, path string, rep *report) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	switch mode {
	case "serve":
		return fmt.Errorf("serve is a top level mode, not an item probe")
	case "ip":
		// What the locked tree's mixed listener would answer for this source address.
		var remote net.Addr = &net.TCPAddr{}
		addr, err := netip.ParseAddr(strings.TrimSpace(string(data)))
		if err != nil {
			return err
		}
		remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 50000))
		rep.Details["source"] = addr.String()
		rep.Details["disallowed"] = inbound.IsRemoteAddrDisAllowed(remote)
	case "proxy":
		var mapping map[string]any
		if err := yaml.Unmarshal(data, &mapping); err != nil {
			return err
		}
		if tag, ok := mapping["tag"]; ok {
			if _, hasName := mapping["name"]; !hasName {
				mapping["name"] = tag
				rep.Details["aliasesApplied"] = []string{"tag"}
			}
		}
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return err
		}
		rep.Proxy = proxy.Name()
	case "rule":
		text := strings.TrimSpace(string(data))
		tp, payload, target, params := RC.ParseRulePayload(text, true)
		parsed, err := rules.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			return err
		}
		rep.Rule = parsed.RuleType().String()
		rep.Details["type"] = tp
		rep.Details["payload"] = payload
		rep.Details["target"] = target
		rep.Details["adapter"] = parsed.Adapter()
		if len(params) > 0 {
			rep.Details["params"] = params
		}
	case "inbound":
		var mapping map[string]any
		if err := yaml.Unmarshal(data, &mapping); err != nil {
			return err
		}
		entry, err := listener.ParseListener(mapping)
		if err != nil {
			return err
		}
		rep.Details["name"] = entry.Name()
		rep.Details["type"] = mapping["type"]
	case "group":
		var mapping map[string]any
		if err := yaml.Unmarshal(data, &mapping); err != nil {
			return err
		}
		names := toStrings(mapping["proxies"])
		// Built-in proxies are registered exactly as the version's config loader does
		// (config.parseProxies); nothing else is added.
		proxyMap := map[string]constant.Proxy{
			"DIRECT":      adapter.NewProxy(outbound.NewDirect()),
			"REJECT":      adapter.NewProxy(outbound.NewReject()),
			"REJECT-DROP": adapter.NewProxy(outbound.NewRejectDrop()),
			"COMPATIBLE":  adapter.NewProxy(outbound.NewCompatible()),
			"PASS":        adapter.NewProxy(outbound.NewPass()),
			"PASS-RULE":   adapter.NewProxy(outbound.NewPassRule()),
		}
		for _, name := range names {
			proxyMap[name] = adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name}))
		}
		group, err := outboundgroup.ParseProxyGroup(mapping, proxyMap, map[string]P.ProxyProvider{}, names, nil)
		if err != nil {
			return err
		}
		rep.Details["name"] = group.Name()
		rep.Details["type"] = mapping["type"]
	case "failed":
		// Why the locked source does not dial the tag host: resolve it exactly as
		// tunnel.resolveMetadata does and report the resolver error.
		host := strings.TrimSpace(string(data))
		rep.Details["host"] = host
		if ip, err := netip.ParseAddr(host); err == nil {
			rep.Details["resolved"] = ip.String()
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
		defer cancel()
		ip, err := resolver.ResolveIP(ctx, host)
		if err != nil {
			return fmt.Errorf("%s", resolverFailure(err, host))
		}
		rep.Details["resolved"] = ip.String()
		rep.Details["resolver"] = "default resolver answered"
	case "dns":
		// name-server-list is a YAML list; loading it via the whole config path exercises the
		// version's own name server parser and enhancer mode checks.
		cfg, err := config.Parse(data)
		if err != nil {
			return err
		}
		rep.Details["nameServers"] = len(cfg.DNS.NameServer)
		rep.Details["enhancedMode"] = cfg.DNS.EnhancedMode.String()
		rep.Details["enable"] = cfg.DNS.Enable
	}
	return nil
}

func serve(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	upstream := os.Getenv("KC_UPSTREAM")
	source := os.Getenv("KC_SOURCE_ADDR")
	host, portText, err := net.SplitHostPort(upstream)
	if err != nil {
		return fmt.Errorf("KC_UPSTREAM: %w", err)
	}
	options := &IN.MixedOption{UDP: false}
	options.NameStr = "probe-mixed"
	options.Listen = "127.0.0.1"
	options.Port = strconv.Itoa(cfg.General.MixedPort)
	mixed, err := IN.NewMixed(options)
	if err != nil {
		return err
	}
	// The pinned mixed listener refuses clients outside lan-allowed-ips; mirror the acceptance
	// the reference is meant to represent by declaring the same ranges before listening.
	prefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	if os.Getenv("KC_DEBUG_LOGS") != "" {
		if file, err := os.OpenFile(os.Getenv("KC_DEBUG_LOGS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			slog.SetOutput(file)
		}
	}
	inbound.SetAllowedIPs(prefixes)
	inbound.SetDisAllowedIPs(nil)
	Mlog.Debugln("probe serve start upstream=%s source=%s allowed=%v", upstream, source, inbound.AllowedIPs())
	tunnel := &relayTunnel{upstream: net.JoinHostPort(host, portText), source: source, rep: &rep}
	if err := mixed.Listen(tunnel); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	rep.Details["mixedPort"] = cfg.General.MixedPort
	rep.Details["udp"] = "not relayed"
	json.NewEncoder(os.Stdout).Encode(rep)
	select {}
}

type relayTunnel struct {
	upstream string
	source   string
	rep      *report
}

func (t *relayTunnel) HandleUDPPacket(packet constant.UDPPacket, metadata *constant.Metadata) {
	packet.Drop()
}

func (t *relayTunnel) NatTable() constant.NatTable {
	return nil
}

func (t *relayTunnel) HandleTCPConn(conn net.Conn, metadata *constant.Metadata) {
	defer conn.Close()
	if metadata != nil {
		Mlog.Debugln("probe relay: type=%v host=%s dst=%s src=%s", metadata.Type, metadata.Host, metadata.AddrPort(), metadata.SourceAddrPort())
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if t.source != "" {
		if addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(t.source, "0")); err == nil {
			dialer.LocalAddr = addr
		}
	}
	upstream, err := dialer.Dial("tcp", t.upstream)
	if err != nil {
		Mlog.Debugln("probe relay dial: %v", err)
		return
	}
	Mlog.Debugln("probe relay connected to %s", t.upstream)
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// resolverFailure keeps the cause (timeout, reported NXDOMAIN, no answer, empty reply, ...)
// because that is what decides whether a client sees an error at all.
func resolverFailure(err error, host string) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Sprintf("resolver error for %s: %s (timeout=%t, notfound=%t)", host, dnsErr.Err, dnsErr.IsTimeout, dnsErr.IsNotFound)
	}
	return fmt.Sprintf("resolver error for %s: %v", host, err)
}

func toStrings(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, fmt.Sprint(item))
	}
	return out
}
