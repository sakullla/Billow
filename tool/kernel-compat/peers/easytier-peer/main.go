// Pinned EasyTier peer used by T20. It runs the locked easytier-go wasm core
// with enable_encryption=false and no secure mode, so the Rust cleartext
// host/discovery handshake can be checked against the real peer. Test-only.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/easytier/easytier/easytier-go/platform"
)

func main() {
	_ = flag.String("mode", "core", "core (kept for the test command line)")
	listen := flag.String("listen", "127.0.0.1:0", "TCP listen address")
	secure := flag.Bool("secure", false, "enable EasyTier secure mode (Noise XX)")
	encrypt := flag.Bool("encrypt", false, "enable EasyTier data encryption")
	logPath := flag.String("log", "", "write peer logs to this file")
	network := flag.String("network", "billow-test", "network name")
	secret := flag.String("secret", "billow-secret", "network secret")
	flag.Parse()

	port := 0
	if _, portText, err := net.SplitHostPort(*listen); err == nil {
		fmt.Sscanf(portText, "%d", &port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var err error
	var logWriter *os.File
	if *logPath != "" {
		logWriter, err = os.Create(*logPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "log:", err)
			os.Exit(1)
		}
		defer logWriter.Close()
	}
	var writer *os.File = logWriter
	if writer == nil {
		writer = os.Stderr
	}
	host, err := corehost.New(ctx, corehost.Options{Platform: platform.Services{}, LogWriter: writer})
	if err != nil {
		fmt.Fprintln(os.Stderr, "host:", err)
		os.Exit(1)
	}
	defer host.Close(ctx)
	builder := corehost.NewInstanceConfigBuilder(*network).
		NetworkSecret(*secret).
		Hostname("billow-t20-core").
		IPv4(netip.MustParsePrefix("10.144.0.1/24")).
		P2P(corehost.P2PPolicy{Disable: true}).
		Encryption(*encrypt).
		AddListeners("tcp://" + *listen)
	if *secure {
		builder = builder.SecureMode()
	}
	config, err := builder.Build()
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
	for i := 0; i < 80; i++ {
		info, err := instance.ShowNodeInfo(ctx)
		if err == nil {
			for _, listener := range info.Listeners {
				if _, portText, err := net.SplitHostPort(listener); err == nil {
					fmt.Sscanf(portText, "%d", &port)
					if port != 0 {
						fmt.Printf("READY %d\n", port)
						time.Sleep(100 * time.Second)
						return
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "listener was not created")
	os.Exit(1)
}
