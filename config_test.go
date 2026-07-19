package main

import (
	"net"
	"testing"
	"time"
)

func TestLoadFlatConfig(t *testing.T) {
	data := []byte(`{"cniVersion":"1.1.0","name":"flat-test","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{"type":"flat-cni-ipam","lookupTimeout":"3s","pollInterval":"20ms"}}`)
	config, cniVersion, timeout, interval, err := LoadFlatConfig(data, "PlatformContainerUUID=platform-a;IPAddress=10.42.5.9")
	if err != nil {
		t.Fatal(err)
	}
	if cniVersion != "1.1.0" || timeout != 3*time.Second || interval != 20*time.Millisecond {
		t.Fatalf("version=%q timeout=%s interval=%s", cniVersion, timeout, interval)
	}
	if string(config.IPAM.PlatformContainerUUID) != "platform-a" || string(config.IPAM.IPAddress) != "10.42.5.9" {
		t.Fatalf("parsed CNI args = %#v", config.IPAM)
	}
}

func TestLoadFlatConfigRejectsInvalidInput(t *testing.T) {
	tests := []string{
		`{"name":"flat-test","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16"}`,
		`{"name":"","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{}}`,
		`{"name":"flat-test","bridge":"","bridgeSubnet":"10.42.0.1/16","ipam":{}}`,
		`{"name":"flat-test","bridge":"bridge0","bridgeSubnet":"not-a-cidr","ipam":{}}`,
		`{"name":"flat-test","bridge":"bridge0","bridgeSubnet":"2001:db8::1/64","ipam":{}}`,
		`{"name":"flat-test","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{"subnetPrefixSize":"16"}}`,
		`{"name":"flat-test","bridge":"bridge0","bridgeSubnet":"10.42.0.1/16","ipam":{"lookupTimeout":"1s","pollInterval":"2s"}}`,
	}
	for _, data := range tests {
		if _, _, _, _, err := LoadFlatConfig([]byte(data), ""); err == nil {
			t.Fatalf("expected invalid config to fail: %s", data)
		}
	}
}

func TestResultAddress(t *testing.T) {
	config := &Net{BridgeSubnet: "10.42.0.1/16", IPAM: &IPAMConfig{}}
	address, err := config.resultAddress("10.42.5.9")
	if err != nil {
		t.Fatal(err)
	}
	if got := address.String(); got != "10.42.5.9/16" {
		t.Fatalf("address = %s", got)
	}
	address, err = config.resultAddress("10.42.5.9/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := address.String(); got != "10.42.5.9/24" {
		t.Fatalf("CIDR address = %s", got)
	}
	config.IPAM.SubnetPrefixSize = "/20"
	address, err = config.resultAddress("10.42.5.9")
	if err != nil || address.String() != "10.42.5.9/20" {
		t.Fatalf("configured prefix address=%s err=%v", address.String(), err)
	}
	for _, invalid := range []string{"", "invalid", "2001:db8::1", "10.42.5.9/99"} {
		if _, err := config.resultAddress(invalid); err == nil {
			t.Fatalf("expected %q to fail", invalid)
		}
	}
}

func TestSelectBridgeGateway(t *testing.T) {
	configured := net.ParseIP("10.42.0.1")
	_, subnet, _ := net.ParseCIDR("10.42.0.0/16")
	addresses := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("10.42.0.9"), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: configured, Mask: net.CIDRMask(16, 32)},
	}
	gateway, err := selectBridgeGateway(configured, subnet, addresses)
	if err != nil || !gateway.Equal(configured) {
		t.Fatalf("gateway=%v err=%v", gateway, err)
	}
	gateway, err = selectBridgeGateway(configured, subnet, addresses[:2])
	if err != nil || gateway.String() != "10.42.0.9" {
		t.Fatalf("single candidate gateway=%v err=%v", gateway, err)
	}
	if _, err := selectBridgeGateway(configured, subnet, addresses[:1]); err == nil {
		t.Fatal("expected no matching gateway to fail")
	}
	ambiguous := append(addresses[:2], &net.IPNet{IP: net.ParseIP("10.42.0.10"), Mask: net.CIDRMask(16, 32)})
	if _, err := selectBridgeGateway(configured, subnet, ambiguous); err == nil {
		t.Fatal("expected ambiguous gateways to fail")
	}
}

func TestMetadataRouteDestinationPrecedence(t *testing.T) {
	t.Setenv("PLATFORM_METADATA_ADDRESS", "192.0.2.30")
	address, err := metadataRouteDestination("192.0.2.20")
	if err != nil || address.String() != "192.0.2.30" {
		t.Fatalf("address=%v err=%v", address, err)
	}
	t.Setenv("PLATFORM_METADATA_ADDRESS", "")
	address, err = metadataRouteDestination("192.0.2.20")
	if err != nil || address.String() != "192.0.2.20" {
		t.Fatalf("configured address=%v err=%v", address, err)
	}
	if _, err := metadataRouteDestination("invalid"); err == nil {
		t.Fatal("expected invalid metadata address to fail")
	}
}
