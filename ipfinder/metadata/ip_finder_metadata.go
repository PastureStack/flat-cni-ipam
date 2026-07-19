package metadata

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 8 << 20

type container struct {
	ExternalID string `json:"external_id"`
	UUID       string `json:"uuid"`
	PrimaryIP  string `json:"primary_ip"`
}

type IPFinderFromMetadata struct {
	endpoint     string
	client       *http.Client
	pollInterval time.Duration
}

func NewIPFinderFromMetadata(rawURL, caRootPath string, pollInterval time.Duration) (*IPFinderFromMetadata, error) {
	parsed, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid metadata URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("metadata URL must not contain credentials, query, or fragment")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caRootPath != "" {
		pem, err := os.ReadFile(caRootPath)
		if err != nil {
			return nil, fmt.Errorf("read metadata CA root: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("metadata CA root contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &IPFinderFromMetadata{
		endpoint:     parsed.String() + "/containers",
		pollInterval: pollInterval,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 3 || request.URL.Host != parsed.Host {
					return fmt.Errorf("metadata redirect rejected")
				}
				return nil
			},
		},
	}, nil
}

func (finder *IPFinderFromMetadata) FindIP(ctx context.Context, containerID, platformID string) (net.IP, error) {
	ticker := time.NewTicker(finder.pollInterval)
	defer ticker.Stop()
	for {
		containers, err := finder.containers(ctx)
		if err != nil {
			return nil, err
		}
		for _, candidate := range containers {
			if candidate.ExternalID != containerID && (platformID == "" || candidate.UUID != platformID) {
				continue
			}
			address := net.ParseIP(candidate.PrimaryIP)
			if address == nil {
				return nil, fmt.Errorf("metadata returned an invalid primary IP")
			}
			return address, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("metadata IP lookup timed out: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (finder *IPFinderFromMetadata) containers(ctx context.Context) ([]container, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, finder.endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := finder.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("metadata containers returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("metadata containers response exceeds %d bytes", maxResponseBytes)
	}
	var containers []container
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("decode metadata containers: %w", err)
	}
	return containers, nil
}
