// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// recordRetryWaits replaces the retry sleep with one that records what it was
// asked to wait and returns immediately, so a test can assert the schedule
// without living through it.
func recordRetryWaits(t *testing.T) *[]time.Duration {
	t.Helper()
	waits := []time.Duration{}
	real := imdsRetryWait
	imdsRetryWait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return ctx.Err()
	}
	t.Cleanup(func() { imdsRetryWait = real })
	return &waits
}

// The schedule is lifted from MSAL .NET's ExponentialRetryStrategy: the first
// wait is the floor and each later one doubles from the delta, capped at the
// ceiling.
func TestIMDSRetryDelayMatchesTheDotNetSchedule(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second, 4 * time.Second}
	for retry, expected := range want {
		if got := imdsRetryDelay(retry); got != expected {
			t.Errorf("imdsRetryDelay(%d) = %v, want %v", retry, got, expected)
		}
	}
}

func TestIMDSRetriableStatusMatchesDotNet(t *testing.T) {
	for _, test := range []struct {
		status int
		want   bool
	}{
		{http.StatusNotFound, true},
		{http.StatusRequestTimeout, true},
		{http.StatusGone, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusServiceUnavailable, true},
		{599, true},
		{http.StatusOK, false},
		{http.StatusMovedPermanently, false},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
	} {
		if got := imdsRetriableStatus(test.status); got != test.want {
			t.Errorf("imdsRetriableStatus(%d) = %v, want %v", test.status, got, test.want)
		}
	}
}

// retryFake serves a canned list of statuses, then 200, recording each request.
type retryFake struct {
	statuses []int
	calls    int
	bodies   []string
}

func (f *retryFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(body))
		i := f.calls
		f.calls++
		if i < len(f.statuses) {
			w.WriteHeader(f.statuses[i])
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func TestSendIMDSRequestRetriesATransientStatus(t *testing.T) {
	waits := recordRetryWaits(t)
	fake := &retryFake{statuses: []int{http.StatusInternalServerError, http.StatusServiceUnavailable}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sendIMDSRequest(context.Background(), srv.Client(), req, true)
	if err != nil {
		t.Fatalf("sendIMDSRequest: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want the third attempt to succeed", resp.StatusCode)
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d, want 3", fake.calls)
	}
	if len(*waits) != 2 || (*waits)[0] != time.Second || (*waits)[1] != 2*time.Second {
		t.Errorf("waits = %v, want [1s 2s]", *waits)
	}
}

// A status that is retriable but never clears must stop after the .NET budget:
// three retries after the first attempt, so four requests in total.
func TestSendIMDSRequestStopsAfterThreeRetries(t *testing.T) {
	waits := recordRetryWaits(t)
	fake := &retryFake{statuses: []int{500, 500, 500, 500, 500, 500}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := sendIMDSRequest(context.Background(), srv.Client(), req, true)
	if err != nil {
		t.Fatalf("sendIMDSRequest: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want the last response to be returned", resp.StatusCode)
	}
	if fake.calls != 4 {
		t.Errorf("calls = %d, want 1 attempt plus 3 retries", fake.calls)
	}
	if len(*waits) != 3 {
		t.Errorf("waits = %v, want three backoffs", *waits)
	}
}

// 410 Gone gets its own budget and a flat interval, because IMDS returns it
// while the endpoint is being brought up rather than for a momentary fault.
func TestSendIMDSRequestGoneUsesTheLinearSchedule(t *testing.T) {
	waits := recordRetryWaits(t)
	fake := &retryFake{statuses: []int{410, 410, 410, 410, 410, 410, 410, 410, 410, 410}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := sendIMDSRequest(context.Background(), srv.Client(), req, true)
	if err != nil {
		t.Fatalf("sendIMDSRequest: %v", err)
	}
	defer resp.Body.Close()

	if fake.calls != 8 {
		t.Errorf("calls = %d, want 1 attempt plus 7 retries", fake.calls)
	}
	if len(*waits) != 7 {
		t.Fatalf("waits = %v, want seven backoffs", *waits)
	}
	for i, w := range *waits {
		if w != imdsGoneRetryAfter {
			t.Errorf("wait %d = %v, want a flat %v", i, w, imdsGoneRetryAfter)
		}
	}
}

// The retry budget is fixed by the first answer, as MSAL .NET does: a request
// that opens with 410 keeps the longer schedule even once the status changes.
func TestSendIMDSRequestKeepsTheBudgetFromTheFirstStatus(t *testing.T) {
	recordRetryWaits(t)
	fake := &retryFake{statuses: []int{410, 500, 500, 500, 500, 500, 500, 500, 500}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := sendIMDSRequest(context.Background(), srv.Client(), req, true)
	if err != nil {
		t.Fatalf("sendIMDSRequest: %v", err)
	}
	defer resp.Body.Close()

	if fake.calls != 8 {
		t.Errorf("calls = %d, want the 410 budget of 1 attempt plus 7 retries", fake.calls)
	}
}

// bodyRecordingClient is an ops.HTTPClient that reads each request body and
// answers from a canned list of statuses. Unlike net/http's transport it does
// not rewind a consumed body from GetBody, which is the point: a caller can
// supply any HTTPClient, so retrying has to hand each attempt a readable body
// rather than assume the client will recover one.
type bodyRecordingClient struct {
	statuses []int
	bodies   []string
}

func (c *bodyRecordingClient) CloseIdleConnections() {}

func (c *bodyRecordingClient) Do(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(b)
	}
	c.bodies = append(c.bodies, body)

	status := http.StatusOK
	if len(c.bodies)-1 < len(c.statuses) {
		status = c.statuses[len(c.bodies)-1]
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

// A body is consumed by the attempt that sends it. Without a rewind the retry
// reaches IMDS with an empty body, which is worse than not retrying at all: the
// credential request would be silently malformed rather than plainly failing.
func TestSendIMDSRequestRewindsTheBodyOnRetry(t *testing.T) {
	recordRetryWaits(t)
	client := &bodyRecordingClient{statuses: []int{500, 500}}

	const payload = `{"csr":"a-certificate-signing-request"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://localhost/issuecredential", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sendIMDSRequest(context.Background(), client, req, true)
	if err != nil {
		t.Fatalf("sendIMDSRequest: %v", err)
	}
	defer resp.Body.Close()

	if len(client.bodies) != 3 {
		t.Fatalf("bodies = %d, want one per attempt", len(client.bodies))
	}
	for i, got := range client.bodies {
		if got != payload {
			t.Errorf("attempt %d sent body %q, want the request replayed in full", i, got)
		}
	}
}

// rewindRequest is also covered directly, because net/http's transport rewinds
// from GetBody on its own: an end-to-end assertion alone would pass even if the
// rewind here were removed.
func TestRewindRequestSuppliesAReadableBody(t *testing.T) {
	const payload = `{"csr":"a-certificate-signing-request"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://localhost/issuecredential", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatal(err)
	}

	rewound, err := rewindRequest(req)
	if err != nil {
		t.Fatalf("rewindRequest: %v", err)
	}
	got, err := io.ReadAll(rewound.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Errorf("rewound body = %q, want %q", got, payload)
	}
	if rewound.ContentLength != int64(len(payload)) {
		t.Errorf("ContentLength = %d, want %d", rewound.ContentLength, len(payload))
	}
}

// A body that cannot be rewound is reported as such, rather than being sent
// empty and failing later as a content-length mismatch.
func TestRewindRequestRejectsABodyItCannotReplay(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://localhost/issuecredential", io.NopCloser(strings.NewReader("x")))
	if err != nil {
		t.Fatal(err)
	}
	if req.GetBody != nil {
		t.Fatal("expected an opaque reader to leave GetBody unset")
	}
	if _, err := rewindRequest(req); err == nil {
		t.Error("rewindRequest succeeded on a body it cannot rewind")
	}
}

func TestSendIMDSRequestDoesNotRetryANonRetriableStatus(t *testing.T) {
	recordRetryWaits(t)
	fake := &retryFake{statuses: []int{http.StatusBadRequest, http.StatusOK}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := sendIMDSRequest(context.Background(), srv.Client(), req, true)
	if err != nil {
		t.Fatalf("sendIMDSRequest: %v", err)
	}
	defer resp.Body.Close()

	if fake.calls != 1 {
		t.Errorf("calls = %d, want a 400 to be reported rather than retried", fake.calls)
	}
}

func TestSendIMDSRequestHonorsADisabledRetryPolicy(t *testing.T) {
	recordRetryWaits(t)
	fake := &retryFake{statuses: []int{500, 500, 500, 500}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := sendIMDSRequest(context.Background(), srv.Client(), req, false)
	if err != nil {
		t.Fatalf("sendIMDSRequest: %v", err)
	}
	defer resp.Body.Close()

	if fake.calls != 1 {
		t.Errorf("calls = %d, want WithRetryPolicyDisabled to send exactly one request", fake.calls)
	}
}

// A canceled caller is not retried: it is already waiting for the error.
func TestSendIMDSRequestDoesNotRetryACanceledContext(t *testing.T) {
	recordRetryWaits(t)
	fake := &retryFake{statuses: []int{500, 500, 500, 500}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	cancel()

	if _, err := sendIMDSRequest(ctx, srv.Client(), req, true); err == nil {
		t.Fatal("sendIMDSRequest succeeded on a canceled context")
	}
	if fake.calls > 1 {
		t.Errorf("calls = %d, want a canceled context not to be retried", fake.calls)
	}
}
