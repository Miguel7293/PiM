package models

import (
	"context"
	"errors"
	"testing"
)

func TestFakeModel(t *testing.T) {
	wantErr := errors.New("model unavailable")
	for _, tc := range []struct {
		name string
		fake FakeModel
	}{
		{"response", FakeModel{Response: "completion"}},
		{"error", FakeModel{Err: wantErr}},
		{"zero value", FakeModel{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var model Model = tc.fake
			got, err := model.Complete(context.Background(), "prompt")
			if got != tc.fake.Response || !errors.Is(err, tc.fake.Err) {
				t.Fatalf("Complete() = %q, %v; want %q, %v", got, err, tc.fake.Response, tc.fake.Err)
			}
		})
	}
}

func TestFakeModelCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := (FakeModel{Response: "unused"}).Complete(ctx, "prompt")
	if got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("Complete() = %q, %v; want empty response and cancellation", got, err)
	}
}
