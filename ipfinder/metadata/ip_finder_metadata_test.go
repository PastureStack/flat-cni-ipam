package metadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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

	finder, err := NewIPFinderFromMetadata(server.URL+"/2015-12-19", "", time.Millisecond)
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
	finder, err := NewIPFinderFromMetadata(server.URL, "", time.Millisecond)
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
	finder, err = NewIPFinderFromMetadata(large.URL, "", time.Millisecond)
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
	finder, err := NewIPFinderFromMetadata(server.URL, "", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := finder.FindIP(ctx, "runtime-a", ""); err == nil {
		t.Fatal("expected lookup timeout")
	}
}
