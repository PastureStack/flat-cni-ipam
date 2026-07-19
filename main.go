package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	platformmetadata "github.com/PastureStack/flat-cni-ipam/ipfinder/metadata"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

var buildVersion = "dev"

const cniLogRoot = "/var/log/pasturestack"
const legacyCNILogPath = "/var/log/pasturestack-cni.log"

type metadataIPFinder interface {
	FindIP(context.Context, string, string) (net.IP, error)
}

var newMetadataFinder = func(rawURL, caRootPath string, pollInterval time.Duration) (metadataIPFinder, error) {
	return platformmetadata.NewIPFinderFromMetadata(rawURL, caRootPath, pollInterval)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "PastureStack flat CNI IPAM "+buildVersion)
}

func cmdAdd(args *skel.CmdArgs) error {
	config, configVersion, lookupTimeout, pollInterval, err := LoadFlatConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	logger, closeLog, err := commandLogger(config.IPAM)
	if err != nil {
		return err
	}
	defer closeLog()

	allocation, err := resolveAddress(config, lookupTimeout, pollInterval, args.ContainerID)
	if err != nil {
		return err
	}
	metadataRoute, err := config.metadataRoute()
	if err != nil {
		return err
	}
	routes := append([]*types.Route{}, config.IPAM.Routes...)
	routes = append(routes, metadataRoute)
	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		IPs:        []*current.IPConfig{{Address: allocation}},
		Routes:     routes,
	}
	if config.IPAM.IsDebugLevel == "true" {
		logger.Print("flat address and metadata route resolved")
	}
	return types.PrintResult(result, configVersion)
}

func cmdCheck(args *skel.CmdArgs) error {
	config, _, lookupTimeout, pollInterval, err := LoadFlatConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	if _, err := resolveAddress(config, lookupTimeout, pollInterval, args.ContainerID); err != nil {
		return err
	}
	_, err = config.metadataRoute()
	return err
}

func cmdDel(*skel.CmdArgs) error {
	return nil
}

func resolveAddress(config *Net, timeout, interval time.Duration, containerID string) (net.IPNet, error) {
	rawAddress := strings.TrimSpace(string(config.IPAM.IPAddress))
	if rawAddress == "" {
		platformID := strings.TrimSpace(string(config.IPAM.PlatformContainerUUID))
		if strings.TrimSpace(containerID) == "" && platformID == "" {
			return net.IPNet{}, fmt.Errorf("metadata lookup requires a container identifier")
		}
		finder, err := newMetadataFinder(metadataURL(config.IPAM.MetadataURL), os.Getenv("PLATFORM_CA_ROOT"), interval)
		if err != nil {
			return net.IPNet{}, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		address, err := finder.FindIP(ctx, containerID, platformID)
		if err != nil {
			return net.IPNet{}, err
		}
		rawAddress = address.String()
	}
	return config.resultAddress(rawAddress)
}

func metadataURL(configured string) string {
	if value := strings.TrimSpace(os.Getenv("PLATFORM_METADATA_URL")); value != "" {
		return value
	}
	if value := strings.TrimSpace(configured); value != "" {
		return value
	}
	return platformmetadata.DefaultMetadataURL
}

func commandLogger(config *IPAMConfig) (*log.Logger, func(), error) {
	var output io.Writer = os.Stderr
	closeLog := func() {}
	if config.LogToFile != "" {
		file, err := openApprovedCommandLog(config.LogToFile)
		if err != nil {
			return nil, nil, err
		}
		output = file
		closeLog = func() { _ = file.Close() }
	}
	return log.New(output, "flat-cni-ipam: ", log.LstdFlags), closeLog, nil
}

func openApprovedCommandLog(requestedPath string) (*os.File, error) {
	if filepath.Clean(strings.TrimSpace(requestedPath)) == legacyCNILogPath {
		return openCommandLogFromRoot(filepath.Dir(legacyCNILogPath), legacyCNILogPath)
	}
	return openCommandLogFromRoot(cniLogRoot, requestedPath)
}

func openCommandLogFromRoot(rootPath, requestedPath string) (*os.File, error) {
	requestedPath = strings.TrimSpace(requestedPath)
	if requestedPath == "" || strings.ContainsRune(requestedPath, '\x00') {
		return nil, fmt.Errorf("CNI log path is empty or invalid")
	}
	rootPath = filepath.Clean(rootPath)
	relativePath := filepath.Clean(requestedPath)
	if filepath.IsAbs(relativePath) {
		var err error
		relativePath, err = filepath.Rel(rootPath, relativePath)
		if err != nil {
			return nil, fmt.Errorf("CNI log path is outside the managed log directory")
		}
	}
	if relativePath == "." || !filepath.IsLocal(relativePath) {
		return nil, fmt.Errorf("CNI log path is outside the managed log directory")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open managed CNI log directory: %w", err)
	}
	defer root.Close()
	file, err := root.OpenFile(relativePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open CNI log file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict CNI log file: %w", err)
	}
	return file, nil
}
