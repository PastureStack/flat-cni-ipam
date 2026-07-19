package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
)

type staticMetadataFinder struct {
	address net.IP
	err     error
}

func (finder staticMetadataFinder) FindIP(context.Context, string, string) (net.IP, error) {
	return finder.address, finder.err
}

func TestCNIHandlersWithMetadataFixture(t *testing.T) {
	originalFinderFactory := newMetadataFinder
	newMetadataFinder = func(string, string, time.Duration) (metadataIPFinder, error) {
		return staticMetadataFinder{address: net.ParseIP("10.42.5.9")}, nil
	}
	defer func() { newMetadataFinder = originalFinderFactory }()

	originalLookup := interfaceAddressLookup
	interfaceAddressLookup = func(name string) ([]net.Addr, error) {
		if name != "bridge0" {
			t.Fatalf("bridge name = %q", name)
		}
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.42.0.1"), Mask: net.CIDRMask(16, 32)}}, nil
	}
	defer func() { interfaceAddressLookup = originalLookup }()

	config := []byte(`{"cniVersion":"1.1.0","name":"flat-smoke","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{"type":"flat-cni-ipam","metadataURL":"http://169.254.169.250/2015-12-19","lookupTimeout":"1s","pollInterval":"10ms"}}`)
	args := &skel.CmdArgs{
		ContainerID: "runtime-smoke",
		Args:        "PlatformContainerUUID=platform-smoke",
		StdinData:   config,
	}

	output, err := captureStdout(func() error { return cmdAdd(args) })
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		IPs []struct {
			Address string `json:"address"`
		} `json:"ips"`
		Routes []struct {
			Destination string `json:"dst"`
			Gateway     string `json:"gw"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode CNI result %q: %v", output, err)
	}
	if len(result.IPs) != 1 || result.IPs[0].Address != "10.42.5.9/16" {
		t.Fatalf("CNI IP result = %s", output)
	}
	if len(result.Routes) != 1 || result.Routes[0].Destination != "169.254.169.250/32" || result.Routes[0].Gateway != "10.42.0.1" {
		t.Fatalf("CNI route result = %s", output)
	}
	if err := cmdCheck(args); err != nil {
		t.Fatal(err)
	}
	if err := cmdDel(args); err != nil {
		t.Fatal(err)
	}
}

func TestDirectAddressDoesNotRequireMetadata(t *testing.T) {
	originalLookup := interfaceAddressLookup
	interfaceAddressLookup = func(string) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.42.0.1"), Mask: net.CIDRMask(16, 32)}}, nil
	}
	defer func() { interfaceAddressLookup = originalLookup }()
	t.Setenv("PLATFORM_METADATA_URL", "://invalid")
	config := []byte(`{"cniVersion":"1.1.0","name":"flat-direct","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{"type":"flat-cni-ipam"}}`)
	args := &skel.CmdArgs{Args: "IPAddress=10.42.5.10/24", StdinData: config}
	output, err := captureStdout(func() error { return cmdAdd(args) })
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(output) {
		t.Fatalf("invalid CNI output: %q", output)
	}
}

func TestMetadataURLPrecedence(t *testing.T) {
	t.Setenv("PLATFORM_METADATA_URL", "http://169.254.169.251/2015-12-19")
	if got := metadataURL("http://169.254.169.250/2015-12-19"); got != "http://169.254.169.251/2015-12-19" {
		t.Fatalf("environment metadata URL = %q", got)
	}
	t.Setenv("PLATFORM_METADATA_URL", "")
	if got := metadataURL("http://169.254.169.251/2015-12-19"); got != "http://169.254.169.251/2015-12-19" {
		t.Fatalf("configured metadata URL = %q", got)
	}
	if got := metadataURL(""); got != "http://169.254.169.250/2015-12-19" {
		t.Fatalf("default metadata URL = %q", got)
	}
}

func TestSupportedCNIResultConversions(t *testing.T) {
	originalLookup := interfaceAddressLookup
	interfaceAddressLookup = func(string) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.42.0.1"), Mask: net.CIDRMask(16, 32)}}, nil
	}
	defer func() { interfaceAddressLookup = originalLookup }()
	for _, cniVersion := range []string{"0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"} {
		config := []byte(`{"cniVersion":"` + cniVersion + `","name":"flat-version","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{"type":"flat-cni-ipam"}}`)
		output, err := captureStdout(func() error {
			return cmdAdd(&skel.CmdArgs{Args: "IPAddress=10.42.5.10/24", StdinData: config})
		})
		if err != nil {
			t.Fatalf("CNI %s: %v", cniVersion, err)
		}
		var result map[string]any
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("CNI %s output %q: %v", cniVersion, output, err)
		}
		if result["cniVersion"] != cniVersion {
			t.Fatalf("CNI result version=%v want=%s", result["cniVersion"], cniVersion)
		}
	}
}

func TestMetadataLookupRequiresIdentifier(t *testing.T) {
	config := &Net{IPAM: &IPAMConfig{}, BridgeSubnet: "10.42.0.1/16"}
	if _, err := resolveAddress(config, time.Second, time.Millisecond, ""); err == nil {
		t.Fatal("expected missing metadata lookup identifiers to fail")
	}
}

func TestResolveAddressPropagatesMetadataFactoryAndLookupErrors(t *testing.T) {
	config := &Net{IPAM: &IPAMConfig{}, BridgeSubnet: "10.42.0.1/16"}
	original := newMetadataFinder
	defer func() { newMetadataFinder = original }()
	newMetadataFinder = func(string, string, time.Duration) (metadataIPFinder, error) {
		return nil, fmt.Errorf("factory failed")
	}
	if _, err := resolveAddress(config, time.Second, time.Millisecond, "runtime-a"); err == nil || !strings.Contains(err.Error(), "factory failed") {
		t.Fatalf("factory error = %v", err)
	}
	newMetadataFinder = func(string, string, time.Duration) (metadataIPFinder, error) {
		return staticMetadataFinder{err: fmt.Errorf("lookup failed")}, nil
	}
	if _, err := resolveAddress(config, time.Second, time.Millisecond, "runtime-a"); err == nil || !strings.Contains(err.Error(), "lookup failed") {
		t.Fatalf("lookup error = %v", err)
	}
}

func TestAddressIPSupportsKnownRepresentations(t *testing.T) {
	if got := addressIP(&net.IPAddr{IP: net.ParseIP("192.0.2.20")}); got.String() != "192.0.2.20" {
		t.Fatalf("IPAddr = %v", got)
	}
	if got := addressIP(stringAddress("192.0.2.21/24")); got.String() != "192.0.2.21" {
		t.Fatalf("CIDR string address = %v", got)
	}
	if got := addressIP(stringAddress("192.0.2.22")); got.String() != "192.0.2.22" {
		t.Fatalf("IP string address = %v", got)
	}
	if got := addressIP(nil); got != nil {
		t.Fatalf("nil address = %v", got)
	}
}

type stringAddress string

func (address stringAddress) Network() string { return "test" }
func (address stringAddress) String() string  { return string(address) }

func TestCommandLoggerRestrictsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	root := t.TempDir()
	path := root + "/plugin.log"
	if err := os.WriteFile(path, []byte("existing"), 0o666); err != nil {
		t.Fatal(err)
	}
	file, err := openCommandLogFromRoot(root, path)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("log mode = %o", got)
	}
	for _, unsafe := range []string{"", root, root + "/../outside.log", "../outside.log"} {
		if file, err := openCommandLogFromRoot(root, unsafe); err == nil {
			_ = file.Close()
			t.Fatalf("expected unsafe log path %q to fail", unsafe)
		}
	}
}

func TestCommandLoggerUsesStandardErrorWithoutFile(t *testing.T) {
	logger, closeLog, err := commandLogger(&IPAMConfig{})
	if err != nil {
		t.Fatal(err)
	}
	closeLog()
	if logger == nil || logger.Writer() != os.Stderr {
		t.Fatal("expected the default logger to use standard error")
	}
}

func TestApprovedCommandLogPreservesLegacyDeploymentPath(t *testing.T) {
	if filepath.ToSlash(filepath.Clean(legacyCNILogPath)) != "/var/log/pasturestack-cni.log" {
		t.Fatalf("legacy log path changed to %q", legacyCNILogPath)
	}
	if cniLogRoot != "/var/log/pasturestack" {
		t.Fatalf("managed log root changed to %q", cniLogRoot)
	}
}

func captureStdout(run func() error) ([]byte, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	original := os.Stdout
	os.Stdout = writer
	runErr := run()
	_ = writer.Close()
	os.Stdout = original
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if runErr != nil {
		return nil, runErr
	}
	return output, readErr
}
