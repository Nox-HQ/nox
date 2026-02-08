package plugin

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_UnlimitedAllowsAll(t *testing.T) {
	rl := NewRateLimiter(0, 0)

	for i := 0; i < 100; i++ {
		if err := rl.AllowRequest(context.Background()); err != nil {
			t.Fatalf("AllowRequest should always succeed when unlimited, got %v", err)
		}
	}
	if err := rl.AllowBandwidth(context.Background(), 1024*1024); err != nil {
		t.Fatalf("AllowBandwidth should always succeed when unlimited, got %v", err)
	}
}

func TestRateLimiter_RequestRateLimit(t *testing.T) {
	// 60 RPM = 1 per second, burst of 60.
	rl := NewRateLimiter(60, 0)

	// First 60 requests should be immediate (burst).
	for i := 0; i < 60; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		err := rl.AllowRequest(ctx)
		cancel()
		if err != nil {
			t.Fatalf("request %d should succeed within burst, got %v", i, err)
		}
	}

	// 61st request should block (burst exhausted, rate is 1/sec).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := rl.AllowRequest(ctx)
	cancel()
	if err == nil {
		t.Error("request after burst should be rate-limited")
	}
}

func TestRateLimiter_BandwidthLimit(t *testing.T) {
	// 1MB/min bandwidth.
	rl := NewRateLimiter(0, 1024*1024)

	// First call with full bandwidth should succeed (burst).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	err := rl.AllowBandwidth(ctx, 1024*1024)
	cancel()
	if err != nil {
		t.Fatalf("first bandwidth request within burst should succeed, got %v", err)
	}

	// Next call should block (burst exhausted).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = rl.AllowBandwidth(ctx2, 1024)
	cancel2()
	if err == nil {
		t.Error("bandwidth request after burst exhaustion should be rate-limited")
	}
}

func TestRateLimiter_ContextCancellation(t *testing.T) {
	rl := NewRateLimiter(1, 0) // 1 RPM = very slow

	// First request uses the burst.
	if err := rl.AllowRequest(context.Background()); err != nil {
		t.Fatalf("first request should succeed, got %v", err)
	}

	// Cancel context immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := rl.AllowRequest(ctx)
	if err == nil {
		t.Error("cancelled context should return error")
	}
}
