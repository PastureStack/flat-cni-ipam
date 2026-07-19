package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
)

func TestCNIHandlersWithMetadataFixture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/2015-12-19/containers" {
			http.NotFound(response, request)
			return
		}
		_, _ = response.Write([]byte(`[{"external_id":"runtime-smoke","uuid":"platform-smoke","primary_ip":"10.42.5.9"}]`))
	}))
	defer server.Close()

	originalLookup := interfaceAddressLookup
	interfaceAddressLookup = func(name string) ([]net.Addr, error) {
		if name != "bridge0" {
			t.Fatalf("bridge name = %q", name)
		}
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.42.0.1"), Mask: net.CIDRMask(16, 32)}}, nil
	}
	defer func() { interfaceAddressLookup = originalLookup }()

	config := []byte(`{"cniVersion":"1.1.0","name":"flat-smoke","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{"type":"flat-cni-ipam","metadataURL":"` + server.URL + `/2015-12-19","lookupTimeout":"1s","pollInterval":"10ms"}}`)
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

func TestCommandLoggerRestrictsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := t.TempDir() + "/plugin.log"
	if err := os.WriteFile(path, []byte("existing"), 0o666); err != nil {
		t.Fatal(err)
	}
	_, closeLog, err := commandLogger(&IPAMConfig{LogToFile: path})
	if err != nil {
		t.Fatal(err)
	}
	closeLog()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("log mode = %o", got)
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
