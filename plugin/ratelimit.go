package plugin

import (
	"context"

	"golang.org/x/time/rate"
)

// RateLimiter enforces per-plugin request and bandwidth rate limits
// using token-bucket algorithm.
type RateLimiter struct {
	requestLimiter   *rate.Limiter
	bandwidthLimiter *rate.Limiter
}

// NewRateLimiter creates a rate limiter with the given constraints.
// A requestsPerMin of 0 means unlimited requests.
// A bandwidthBytesPerMin of 0 means unlimited bandwidth.
func NewRateLimiter(requestsPerMin int, bandwidthBytesPerMin int64) *RateLimiter {
	rl := &RateLimiter{}

	if requestsPerMin > 0 {
		r := rate.Limit(float64(requestsPerMin) / 60.0)
		rl.requestLimiter = rate.NewLimiter(r, requestsPerMin)
	}

	if bandwidthBytesPerMin > 0 {
		r := rate.Limit(float64(bandwidthBytesPerMin) / 60.0)
		rl.bandwidthLimiter = rate.NewLimiter(r, int(bandwidthBytesPerMin))
	}

	return rl
}

// AllowRequest blocks until the request is allowed or the context is done.
// Returns nil immediately if request rate limiting is disabled.
func (rl *RateLimiter) AllowRequest(ctx context.Context) error {
	if rl.requestLimiter == nil {
		return nil
	}
	return rl.requestLimiter.Wait(ctx)
}

// AllowBandwidth blocks until the given number of bytes is allowed or the
// context is done. Returns nil immediately if bandwidth limiting is disabled.
func (rl *RateLimiter) AllowBandwidth(ctx context.Context, bytes int64) error {
	if rl.bandwidthLimiter == nil {
		return nil
	}
	return rl.bandwidthLimiter.WaitN(ctx, int(bytes))
}
