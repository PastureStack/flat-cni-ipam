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
	"strconv"
	"strings"
	"time"
)

const (
	maxResponseBytes       = 8 << 20
	defaultMetadataHost    = "169.254.169.250"
	alternateMetadataHost  = "169.254.169.251"
	metadataVersionPath    = "/2015-12-19"
	metadataContainersPath = metadataVersionPath + "/containers"
	metadataCARootPath     = "/etc/pasturestack/certs/metadata-ca.pem"

	// DefaultMetadataURL is the fixed link-local metadata endpoint used by the
	// supported control-plane deployment contract.
	DefaultMetadataURL = "http://" + defaultMetadataHost + metadataVersionPath
)

type container struct {
	ExternalID string `json:"external_id"`
	UUID       string `json:"uuid"`
	PrimaryIP  string `json:"primary_ip"`
}

type metadataOriginPolicy struct {
	origin string
}

type policyTransport struct {
	base   http.RoundTripper
	policy *metadataOriginPolicy
}

func (transport *policyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet {
		return nil, fmt.Errorf("metadata request is invalid")
	}
	requestURL := request.URL.String()
	if transport == nil || transport.policy == nil || !isValidRedirectURL(requestURL, transport.policy) {
		return nil, fmt.Errorf("metadata request destination is not authorized")
	}
	base := transport.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(request)
}

type IPFinderFromMetadata struct {
	endpoint     string
	policy       *metadataOriginPolicy
	client       *http.Client
	pollInterval time.Duration
}

func NewIPFinderFromMetadata(rawURL, caRootPath string, pollInterval time.Duration) (*IPFinderFromMetadata, error) {
	if pollInterval <= 0 {
		return nil, fmt.Errorf("metadata poll interval must be positive")
	}
	endpoint, policy, err := approvedMetadataEndpoint(rawURL)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// A node-local metadata request must never be redirected through an ambient
	// proxy, where its response or future credentials could be exposed.
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caRootPath != "" {
		pem, err := readApprovedMetadataCARoot(caRootPath)
		if err != nil {
			return nil, err
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
		endpoint:     endpoint,
		policy:       policy,
		pollInterval: pollInterval,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &policyTransport{base: transport, policy: policy},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func approvedMetadataEndpoint(rawURL string) (string, *metadataOriginPolicy, error) {
	if rawURL == "" || rawURL != strings.TrimSpace(rawURL) || strings.ContainsAny(rawURL, "\r\n\t") {
		return "", nil, fmt.Errorf("invalid metadata URL")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return "", nil, fmt.Errorf("invalid metadata URL")
	}
	if parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", nil, fmt.Errorf("metadata URL must not contain credentials, encoded path, query, or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path != metadataVersionPath {
		return "", nil, fmt.Errorf("metadata URL must use the supported API path")
	}
	origin, err := canonicalMetadataOrigin(parsed)
	if err != nil {
		return "", nil, err
	}
	if !isApprovedMetadataHost(parsed.Hostname()) {
		return "", nil, fmt.Errorf("metadata URL must use a reserved platform metadata address")
	}
	if !usesStandardPort(parsed) {
		return "", nil, fmt.Errorf("metadata URL must use its scheme's standard port")
	}
	parsed.Path = metadataContainersPath
	endpoint := parsed.String()
	policy := &metadataOriginPolicy{origin: origin}
	if !isValidRedirectURL(endpoint, policy) {
		return "", nil, fmt.Errorf("metadata request destination is not authorized")
	}
	return endpoint, policy, nil
}

func readApprovedMetadataCARoot(requestedPath string) ([]byte, error) {
	requestedPath = strings.TrimSpace(requestedPath)
	if requestedPath != metadataCARootPath {
		return nil, fmt.Errorf("metadata CA root must use %s", metadataCARootPath)
	}
	// The operator opts into a single managed mount path. The value passed to
	// the filesystem is constant and cannot be selected by CNI input or the
	// process environment.
	pem, err := os.ReadFile(metadataCARootPath)
	if err != nil {
		return nil, fmt.Errorf("read metadata CA root: %w", err)
	}
	return pem, nil
}

func canonicalMetadataOrigin(parsed *url.URL) (string, error) {
	if parsed == nil {
		return "", fmt.Errorf("metadata URL is missing")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("metadata URL must use http or https")
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if hostname == "" {
		return "", fmt.Errorf("metadata URL must include a host")
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("metadata URL contains an invalid port")
	}
	return scheme + "://" + net.JoinHostPort(hostname, port), nil
}

func isApprovedMetadataHost(hostname string) bool {
	address := net.ParseIP(hostname)
	if address == nil || address.To4() == nil {
		return false
	}
	canonical := address.String()
	return canonical == defaultMetadataHost || canonical == alternateMetadataHost
}

func usesStandardPort(parsed *url.URL) bool {
	if parsed == nil || parsed.Port() == "" {
		return true
	}
	return (strings.EqualFold(parsed.Scheme, "http") && parsed.Port() == "80") ||
		(strings.EqualFold(parsed.Scheme, "https") && parsed.Port() == "443")
}

// isValidRedirectURL verifies the exact value handed to the HTTP stack.
// Construction-time validation is repeated by policyTransport at the final
// network boundary so future callers cannot change the approved destination.
func isValidRedirectURL(rawURL string, policy *metadataOriginPolicy) bool {
	if policy == nil {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != metadataContainersPath {
		return false
	}
	origin, err := canonicalMetadataOrigin(parsed)
	return err == nil && origin == policy.origin
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
	if finder == nil || finder.client == nil || finder.policy == nil {
		return nil, fmt.Errorf("metadata client is not configured")
	}
	requestURL := finder.endpoint
	if !isValidRedirectURL(requestURL, finder.policy) {
		return nil, fmt.Errorf("metadata request destination is not authorized")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
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
