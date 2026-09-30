package parallel

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
)

func TestMapKeepsInputOrder(t *testing.T) {
	got, err := Map(context.Background(), 1000, func(i int) (int, error) { return i * i, nil })
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range got {
		if v != i*i {
			t.Fatalf("out[%d] = %d, want %d", i, v, i*i)
		}
	}
}

func TestMapReportsTheLowestFailingIndex(t *testing.T) {
	// Every index from 300 on fails; a sequential loop stops at 300, so that
	// is the error Map must report however the work was scheduled.
	for range 50 {
		_, err := Map(context.Background(), 1000, func(i int) (int, error) {
			if i >= 300 {
				return 0, fmt.Errorf("item %d", i)
			}
			return i, nil
		})
		if err == nil || err.Error() != "item 300" {
			t.Fatalf("err = %v, want item 300", err)
		}
	}
}

func TestMapStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ran atomic.Int64
	_, err := Map(ctx, 100, func(i int) (int, error) { ran.Add(1); return i, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if ran.Load() != 0 {
		t.Fatalf("%d items ran after cancellation", ran.Load())
	}
}

func TestMapEmpty(t *testing.T) {
	got, err := Map(context.Background(), 0, func(int) (int, error) { t.Fatal("called"); return 0, nil })
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}
