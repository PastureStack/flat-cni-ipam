package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/types"
)

const (
	defaultLookupTimeout   = 2 * time.Minute
	defaultPollInterval    = 500 * time.Millisecond
	defaultMetadataAddress = "169.254.169.250"
)

type IPAMConfig struct {
	types.CommonArgs
	Type                  string                     `json:"type"`
	LogToFile             string                     `json:"logToFile"`
	IsDebugLevel          string                     `json:"isDebugLevel"`
	SubnetPrefixSize      string                     `json:"subnetPrefixSize"`
	Routes                []*types.Route             `json:"routes"`
	MetadataURL           string                     `json:"metadataURL"`
	MetadataAddress       string                     `json:"metadataAddress"`
	LookupTimeout         string                     `json:"lookupTimeout"`
	PollInterval          string                     `json:"pollInterval"`
	PlatformContainerUUID types.UnmarshallableString `json:"platformContainerUUID,omitempty"`
	IPAddress             types.UnmarshallableString `json:"ipAddress,omitempty"`
}

type Net struct {
	Name         string      `json:"name"`
	CNIVersion   string      `json:"cniVersion"`
	IPAM         *IPAMConfig `json:"ipam"`
	BridgeSubnet string      `json:"bridgeSubnet"`
	Bridge       string      `json:"bridge"`
}

var interfaceAddressLookup = func(name string) ([]net.Addr, error) {
	bridge, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return bridge.Addrs()
}

func LoadFlatConfig(data []byte, args string) (*Net, string, time.Duration, time.Duration, error) {
	config := Net{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, "", 0, 0, fmt.Errorf("load network config: %w", err)
	}
	if config.IPAM == nil {
		return nil, "", 0, 0, fmt.Errorf("IPAM config missing 'ipam' key")
	}
	if strings.TrimSpace(config.Name) == "" {
		return nil, "", 0, 0, fmt.Errorf("network config missing 'name'")
	}
	if strings.TrimSpace(config.Bridge) == "" {
		return nil, "", 0, 0, fmt.Errorf("network config missing 'bridge'")
	}
	if _, _, err := config.bridgeNetwork(); err != nil {
		return nil, "", 0, 0, err
	}
	if config.IPAM.SubnetPrefixSize != "" {
		if _, err := parseIPv4Prefix(config.IPAM.SubnetPrefixSize); err != nil {
			return nil, "", 0, 0, err
		}
	}
	if args != "" {
		if err := types.LoadArgs(args, config.IPAM); err != nil {
			return nil, "", 0, 0, fmt.Errorf("parse CNI args: %w", err)
		}
	}
	if config.CNIVersion == "" {
		config.CNIVersion = "0.1.0"
	}
	lookupTimeout, err := parseDuration(config.IPAM.LookupTimeout, defaultLookupTimeout, "lookupTimeout")
	if err != nil {
		return nil, "", 0, 0, err
	}
	pollInterval, err := parseDuration(config.IPAM.PollInterval, defaultPollInterval, "pollInterval")
	if err != nil {
		return nil, "", 0, 0, err
	}
	if pollInterval > lookupTimeout {
		return nil, "", 0, 0, fmt.Errorf("pollInterval must not exceed lookupTimeout")
	}
	return &config, config.CNIVersion, lookupTimeout, pollInterval, nil
}

func parseDuration(value string, fallback time.Duration, name string) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid %s", name)
	}
	return duration, nil
}

func parseIPv4Prefix(value string) (int, error) {
	if !strings.HasPrefix(value, "/") {
		return 0, fmt.Errorf("subnetPrefixSize must begin with '/'")
	}
	prefix, err := strconv.Atoi(strings.TrimPrefix(value, "/"))
	if err != nil || prefix < 0 || prefix > 32 {
		return 0, fmt.Errorf("invalid IPv4 subnetPrefixSize")
	}
	return prefix, nil
}

func (config *Net) bridgeNetwork() (net.IP, *net.IPNet, error) {
	bridgeIP, network, err := net.ParseCIDR(strings.TrimSpace(config.BridgeSubnet))
	if err != nil || bridgeIP.To4() == nil {
		return nil, nil, fmt.Errorf("bridgeSubnet must be a valid IPv4 CIDR")
	}
	return bridgeIP.To4(), network, nil
}

func (config *Net) subnetPrefix() (int, error) {
	if config.IPAM.SubnetPrefixSize != "" {
		return parseIPv4Prefix(config.IPAM.SubnetPrefixSize)
	}
	_, network, err := config.bridgeNetwork()
	if err != nil {
		return 0, err
	}
	prefix, bits := network.Mask.Size()
	if bits != 32 {
		return 0, fmt.Errorf("bridgeSubnet must be IPv4")
	}
	return prefix, nil
}

func (config *Net) resultAddress(value string) (net.IPNet, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		address, network, err := net.ParseCIDR(value)
		if err != nil || address.To4() == nil {
			return net.IPNet{}, fmt.Errorf("assigned address must be a valid IPv4 CIDR")
		}
		return net.IPNet{IP: address.To4(), Mask: network.Mask}, nil
	}
	address := net.ParseIP(value)
	if address == nil || address.To4() == nil {
		return net.IPNet{}, fmt.Errorf("assigned address must be a valid IPv4 address")
	}
	prefix, err := config.subnetPrefix()
	if err != nil {
		return net.IPNet{}, err
	}
	return net.IPNet{IP: address.To4(), Mask: net.CIDRMask(prefix, 32)}, nil
}

func (config *Net) metadataRoute() (*types.Route, error) {
	destination, err := metadataRouteDestination(config.IPAM.MetadataAddress)
	if err != nil {
		return nil, err
	}
	configuredBridgeIP, bridgeNetwork, err := config.bridgeNetwork()
	if err != nil {
		return nil, err
	}
	addresses, err := interfaceAddressLookup(config.Bridge)
	if err != nil {
		return nil, fmt.Errorf("read bridge %q addresses: %w", config.Bridge, err)
	}
	gateway, err := selectBridgeGateway(configuredBridgeIP, bridgeNetwork, addresses)
	if err != nil {
		return nil, fmt.Errorf("select bridge %q gateway: %w", config.Bridge, err)
	}
	return &types.Route{
		Dst: net.IPNet{IP: destination, Mask: net.CIDRMask(32, 32)},
		GW:  gateway,
	}, nil
}

func metadataRouteDestination(configured string) (net.IP, error) {
	value := strings.TrimSpace(os.Getenv("PLATFORM_METADATA_ADDRESS"))
	if value == "" {
		value = strings.TrimSpace(configured)
	}
	if value == "" {
		value = defaultMetadataAddress
	}
	address := net.ParseIP(value)
	if address == nil || address.To4() == nil {
		return nil, fmt.Errorf("metadataAddress must be a valid IPv4 address")
	}
	return address.To4(), nil
}

func selectBridgeGateway(configured net.IP, subnet *net.IPNet, addresses []net.Addr) (net.IP, error) {
	candidates := make([]net.IP, 0, len(addresses))
	for _, candidate := range addresses {
		address := addressIP(candidate)
		if address == nil || address.To4() == nil || !subnet.Contains(address) {
			continue
		}
		address = address.To4()
		if address.Equal(configured) {
			return address, nil
		}
		candidates = append(candidates, address)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no IPv4 address belongs to bridgeSubnet")
	}
	if len(candidates) > 1 {
		return nil, fmt.Errorf("multiple IPv4 addresses belong to bridgeSubnet and none matches its configured address")
	}
	return candidates[0], nil
}

func addressIP(address net.Addr) net.IP {
	if address == nil {
		return nil
	}
	switch value := address.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		raw := address.String()
		if parsed, _, err := net.ParseCIDR(raw); err == nil {
			return parsed
		}
		return net.ParseIP(raw)
	}
}
