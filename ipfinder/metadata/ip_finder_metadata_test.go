package metadata

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type recordingTransport struct {
	requests int
}

func (transport *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests++
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`[]`)),
		Request:    request,
	}, nil
}

func TestFinderRejectsUnapprovedMetadataOrigins(t *testing.T) {
	for _, value := range []string{
		"http://127.0.0.1/2015-12-19",
		"http://169.254.169.254/latest/meta-data",
		"http://169.254.169.250:8080/2015-12-19",
		"https://169.254.169.250:8443/2015-12-19",
		"https://metadata.example.test/2015-12-19",
	} {
		if _, err := NewIPFinderFromMetadata(value, "", time.Millisecond); err == nil {
			t.Fatalf("expected unapproved metadata origin %q to fail", value)
		}
	}
}

func TestFinderAcceptsSupportedLinkLocalMetadataOrigins(t *testing.T) {
	for _, value := range []string{
		"http://169.254.169.250/2015-12-19",
		"https://169.254.169.251/2015-12-19/",
	} {
		finder, err := NewIPFinderFromMetadata(value, "", time.Millisecond)
		if err != nil {
			t.Fatalf("expected supported metadata origin %q: %v", value, err)
		}
		if finder.endpoint == "" || finder.policy == nil {
			t.Fatalf("metadata origin %q produced an incomplete client", value)
		}
	}
}

func TestFinderRejectsInvalidPollInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Millisecond} {
		if _, err := NewIPFinderFromMetadata(DefaultMetadataURL, "", interval); err == nil {
			t.Fatalf("expected poll interval %s to fail", interval)
		}
	}
}

func TestFinderRejectsUnapprovedCARootPath(t *testing.T) {
	path := t.TempDir() + "/metadata-ca.pem"
	if _, err := NewIPFinderFromMetadata("https://169.254.169.250/2015-12-19", path, time.Millisecond); err == nil {
		t.Fatal("expected an arbitrary CA root path to fail")
	}
	if _, err := readApprovedMetadataCARoot(metadataCARootPath); err == nil || !strings.Contains(err.Error(), "read metadata CA root") {
		t.Fatalf("expected the approved missing mount to reach only the fixed path: %v", err)
	}
}

func TestPolicyTransportRejectsChangedMetadataDestination(t *testing.T) {
	approved, err := url.Parse("http://169.254.169.250" + metadataContainersPath)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := canonicalMetadataOrigin(approved)
	if err != nil {
		t.Fatal(err)
	}
	base := &recordingTransport{}
	transport := &policyTransport{base: base, policy: &metadataOriginPolicy{origin: origin}}
	client := &http.Client{Transport: transport}
	for _, denied := range []string{
		"http://169.254.169.251" + metadataContainersPath,
		"https://169.254.169.250" + metadataContainersPath,
		"http://169.254.169.250:8080" + metadataContainersPath,
		"http://169.254.169.250/latest/meta-data",
		"http://127.0.0.1" + metadataContainersPath,
	} {
		if _, err := client.Get(denied); err == nil {
			t.Fatalf("changed metadata destination %q was accepted", denied)
		}
	}
	if base.requests != 0 {
		t.Fatalf("unauthorized requests reached the network %d times", base.requests)
	}
	response, err := client.Get("http://169.254.169.250" + metadataContainersPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if base.requests != 1 {
		t.Fatalf("approved request reached the network %d times", base.requests)
	}
}

func TestPolicyTransportRejectsInvalidRequestShape(t *testing.T) {
	base := &recordingTransport{}
	policy := &metadataOriginPolicy{origin: "http://169.254.169.250:80"}
	transport := &policyTransport{base: base, policy: policy}
	if _, err := transport.RoundTrip(nil); err == nil {
		t.Fatal("expected nil request to fail")
	}
	request, err := http.NewRequest(http.MethodPost, "http://169.254.169.250"+metadataContainersPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("expected non-GET metadata request to fail")
	}
	if base.requests != 0 {
		t.Fatalf("invalid requests reached the network %d times", base.requests)
	}
}

func TestCanonicalMetadataOriginRejectsInvalidValues(t *testing.T) {
	for _, rawURL := range []string{
		"ftp://169.254.169.250/2015-12-19",
		"http:///2015-12-19",
		"http://169.254.169.250:70000/2015-12-19",
	} {
		parsed, _ := url.Parse(rawURL)
		if _, err := canonicalMetadataOrigin(parsed); err == nil {
			t.Fatalf("expected invalid origin %q to fail", rawURL)
		}
	}
	if _, err := canonicalMetadataOrigin(nil); err == nil {
		t.Fatal("expected nil origin to fail")
	}
}

func TestMetadataClientRejectsInvalidState(t *testing.T) {
	var finder *IPFinderFromMetadata
	if _, err := finder.containers(context.Background()); err == nil {
		t.Fatal("expected nil metadata client to fail")
	}
	policy := &metadataOriginPolicy{origin: "http://169.254.169.250:80"}
	finder = &IPFinderFromMetadata{
		endpoint: "http://169.254.169.251" + metadataContainersPath,
		policy:   policy,
		client:   &http.Client{Transport: &recordingTransport{}},
	}
	if _, err := finder.containers(context.Background()); err == nil {
		t.Fatal("expected mutated metadata endpoint to fail before the network")
	}
}

func TestFinderDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	finder, err := newTestIPFinder(redirector.URL, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.containers(context.Background()); err == nil {
		t.Fatal("expected redirect response to fail")
	}
	if redirected.Load() {
		t.Fatal("metadata request followed a redirect")
	}
}

func TestFinderPollsAndMatchesBothIdentifiers(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/2015-12-19/containers" {
			http.NotFound(response, request)
			return
		}
		if calls.Add(1) == 1 {
			_, _ = response.Write([]byte(`[]`))
			return
		}
		_, _ = response.Write([]byte(`[{"external_id":"runtime-a","uuid":"platform-a","primary_ip":"192.0.2.25"}]`))
	}))
	defer server.Close()

	finder, err := newTestIPFinder(server.URL, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	address, err := finder.FindIP(ctx, "missing", "platform-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := address.String(); got != "192.0.2.25" {
		t.Fatalf("address = %s", got)
	}
}

func TestFinderRejectsInvalidAndOversizedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[{"external_id":"runtime-a","primary_ip":"not-an-address"}]`))
	}))
	defer server.Close()
	finder, err := newTestIPFinder(server.URL, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.FindIP(context.Background(), "runtime-a", ""); err == nil {
		t.Fatal("expected invalid address to fail")
	}

	large := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[]` + strings.Repeat(" ", maxResponseBytes)))
	}))
	defer large.Close()
	finder, err = newTestIPFinder(large.URL, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.FindIP(context.Background(), "runtime-a", ""); err == nil {
		t.Fatal("expected oversized response to fail")
	}
}

func TestFinderRejectsUnsafeURLAndTimesOut(t *testing.T) {
	credentialURL := "http://user" + ":" + "pass@" + "metadata.invalid/path"
	for _, value := range []string{"metadata", "ftp://metadata/path", credentialURL, "http://metadata/path?token=value"} {
		if _, err := NewIPFinderFromMetadata(value, "", time.Millisecond); err == nil {
			t.Fatalf("expected %q to fail", value)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	finder, err := newTestIPFinder(server.URL, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := finder.FindIP(ctx, "runtime-a", ""); err == nil {
		t.Fatal("expected lookup timeout")
	}
}

func newTestIPFinder(rawURL string, interval time.Duration) (*IPFinderFromMetadata, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	parsed.Path = metadataContainersPath
	origin, err := canonicalMetadataOrigin(parsed)
	if err != nil {
		return nil, err
	}
	policy := &metadataOriginPolicy{origin: origin}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &IPFinderFromMetadata{
		endpoint:     parsed.String(),
		policy:       policy,
		pollInterval: interval,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &policyTransport{base: transport, policy: policy},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}
