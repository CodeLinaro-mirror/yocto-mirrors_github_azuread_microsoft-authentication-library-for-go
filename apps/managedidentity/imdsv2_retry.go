// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// The IMDSv2 legs retry on the same conditions and with the same timing as
// MSAL .NET's ImdsRetryPolicy, so that a host which is slow to bring IMDS up
// behaves the same way whichever library is asking.
//
// Two strategies exist because 410 Gone means something different from the
// other retriable answers. IMDS returns it while the endpoint is being brought
// up or moved, which resolves on a scale of a minute rather than seconds, so it
// is retried longer and at a flat interval instead of backing off.
const (
	// imdsExponentialRetries is the number of retries after the first attempt
	// for every retriable status except 410.
	imdsExponentialRetries = 3
	// imdsLinearRetries is the number of retries after the first attempt for
	// 410 Gone.
	imdsLinearRetries = 7

	imdsMinBackoff     = 1 * time.Second
	imdsMaxBackoff     = 4 * time.Second
	imdsDeltaBackoff   = 2 * time.Second
	imdsGoneRetryAfter = 10 * time.Second
)

// imdsRetriableStatus reports whether an IMDS response should be retried. It
// mirrors HttpRetryConditions.Imds in MSAL .NET.
//
// 404 is retriable even though this package treats a persistent 404 as the
// capability answer "this host only serves IMDSv1". A single 404 can also come
// from an agent that has not finished starting, so the answer is only believed
// after the retries are exhausted.
func imdsRetriableStatus(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusRequestTimeout, http.StatusGone, http.StatusTooManyRequests:
		return true
	}
	return status >= 500 && status <= 599
}

// imdsRetriableError reports whether a transport-level failure should be
// retried. MSAL .NET retries exactly one exception here, TaskCanceledException,
// which is what its HTTP client raises on a timeout; the Go equivalent is a
// timeout from the client or from a per-request deadline.
//
// A context that the caller canceled is never retried: the caller has already
// given up, so another attempt would only delay the error it is waiting for.
func imdsRetriableError(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// imdsRetryDelay is how long to wait before the retry numbered retry, counting
// from zero. It reproduces ExponentialRetryStrategy.CalculateDelay: the first
// wait is the floor, and every later one doubles from the delta up to the
// ceiling, giving 1s, 2s, 4s.
func imdsRetryDelay(retry int) time.Duration {
	if retry <= 0 {
		return imdsMinBackoff
	}
	delay := time.Duration(1<<(retry-1)) * imdsDeltaBackoff
	if delay > imdsMaxBackoff {
		return imdsMaxBackoff
	}
	return delay
}

// imdsRetryWait sleeps for d unless ctx ends first. It is a variable so tests
// can observe the schedule without waiting out a real backoff.
var imdsRetryWait = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sendIMDSRequest sends req and retries it while IMDS answers with something
// transient. It returns the last response received, so the caller applies its
// own meaning to a status that survived the retries.
//
// req is cloned per attempt and its body rewound from GetBody, because a body
// is consumed by the attempt that sent it. http.NewRequest populates GetBody
// for the in-memory body types this package uses; a request without one is sent
// once rather than replayed empty.
func sendIMDSRequest(ctx context.Context, client ops.HTTPClient, req *http.Request, retryEnabled bool) (*http.Response, error) {
	if !retryEnabled {
		return client.Do(req)
	}

	// The number of retries is fixed by the first answer, as MSAL .NET does:
	// a request that starts out as 410 keeps the longer schedule even if a
	// later attempt fails differently.
	maxRetries := -1

	var resp *http.Response
	var err error
	for retry := 0; ; retry++ {
		attempt := req
		if retry > 0 {
			attempt, err = rewindRequest(req)
			if err != nil {
				return nil, err
			}
		}

		resp, err = client.Do(attempt)

		retriable := false
		switch {
		case err != nil:
			retriable = imdsRetriableError(ctx, err)
			if maxRetries < 0 {
				maxRetries = imdsExponentialRetries
			}
		default:
			retriable = imdsRetriableStatus(resp.StatusCode)
			if maxRetries < 0 {
				maxRetries = imdsExponentialRetries
				if resp.StatusCode == http.StatusGone {
					maxRetries = imdsLinearRetries
				}
			}
		}

		if !retriable || retry >= maxRetries {
			return resp, err
		}

		delay := imdsRetryDelay(retry)
		if resp != nil && resp.StatusCode == http.StatusGone {
			delay = imdsGoneRetryAfter
		}

		// The response is discarded, so its body is drained before it is
		// closed: that lets the transport reuse the connection for the retry
		// instead of opening a new one.
		drainResponse(resp)

		if waitErr := imdsRetryWait(ctx, delay); waitErr != nil {
			return nil, waitErr
		}
	}
}

// rewindRequest clones req with a fresh body so it can be sent again.
//
// The clone shares req's body reader, which the previous attempt has already
// read to EOF, so the body is replaced from GetBody. net/http's own transport
// would rewind from GetBody too, but ops.HTTPClient is an interface and a
// caller-supplied client is under no obligation to do so, so the rewind is done
// here rather than relied upon.
func rewindRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return clone, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("managedidentity: the IMDS request cannot be retried because its body cannot be rewound")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

// drainResponse reads and closes a response that is being thrown away.
func drainResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}
