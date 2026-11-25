package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Miguel7293/PiM-/internal/findings"
	"github.com/Miguel7293/PiM-/internal/graph"
)

type fakeAgent struct {
	name string
	run  func(context.Context, *Scan) error
}

func (a fakeAgent) Name() string                           { return a.name }
func (a fakeAgent) Run(ctx context.Context, s *Scan) error { return a.run(ctx, s) }

type eventSink struct{ events []Event }

func (s *eventSink) Emit(e Event) { s.events = append(s.events, e) }

func TestRunSequential(t *testing.T) {
	failure := errors.New("failure")
	for _, mode := range []string{"success", "error", "cancel", "precancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scan := &Scan{ID: "scan", Target: "target", Scope: "authorized", Structure: &graph.StructureGraph{}, Findings: &findings.Set{}}
			sink := &eventSink{}
			var calls []string
			makeAgent := func(name string) Agent {
				return fakeAgent{name, func(got context.Context, s *Scan) error {
					if got != ctx || s != scan {
						t.Fatal("scan/context changed")
					}
					calls = append(calls, name)
					if name == "a" {
						if mode == "error" {
							return failure
						}
						if mode == "cancel" {
							cancel()
						}
					}
					return nil
				}}
			}
			if mode == "precancel" {
				cancel()
			}
			err := RunSequential(ctx, scan, sink, makeAgent("a"), makeAgent("b"))
			var wantCalls []string
			var kinds []EventKind
			switch mode {
			case "success":
				wantCalls = []string{"a", "b"}
				kinds = []EventKind{Started, Finished, Started, Finished}
				if err != nil {
					t.Fatal(err)
				}
			case "error", "cancel":
				wantCalls = []string{"a"}
				kinds = []EventKind{Started, Failed}
				want := failure
				if mode == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(err, want) || !strings.Contains(err.Error(), "a") {
					t.Fatalf("error: %v", err)
				}
			case "precancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(calls, wantCalls) || len(sink.events) != len(kinds) {
				t.Fatalf("calls/events: %v %+v", calls, sink.events)
			}
			for i, e := range sink.events {
				if e.Kind != kinds[i] || e.ScanID != scan.ID || e.Agent != calls[i/2] || e.Time.IsZero() {
					t.Fatalf("event: %+v", e)
				}
				if i > 0 && e.Time.Before(sink.events[i-1].Time) {
					t.Fatal("event time order")
				}
				if e.Kind == Failed && e.Message == "" {
					t.Fatal("missing failure message")
				}
			}
		})
	}
}

func TestOptionalSinkAndInvalidArguments(t *testing.T) {
	ctx := context.Background()
	scan := &Scan{}
	agent := fakeAgent{"ok", func(context.Context, *Scan) error { return nil }}
	for _, sink := range []Sink{nil, NopSink{}} {
		if err := RunSequential(ctx, scan, sink, agent); err != nil {
			t.Fatal(err)
		}
	}
	if err := RunSequential(ctx, scan, nil); err != nil {
		t.Fatal(err)
	}
	if RunSequential(ctx, nil, nil) == nil || RunSequential(ctx, scan, nil, nil) == nil {
		t.Fatal("accepted nil argument")
	}
}
