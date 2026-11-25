// Package orchestrator defines scan and agent contracts and minimal execution.
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/Miguel7293/PiM-/internal/findings"
	"github.com/Miguel7293/PiM-/internal/graph"
)

// Scan carries the user-authorized scope and shared results of a scan.
type Scan struct {
	ID        string                `json:"id"`
	Target    string                `json:"target"`
	Scope     string                `json:"scope"`
	StartedAt time.Time             `json:"started_at"`
	Structure *graph.StructureGraph `json:"structure"`
	Findings  *findings.Set         `json:"findings"`
}

// Agent performs one scan step and must cooperate with context cancellation.
type Agent interface {
	Name() string
	Run(ctx context.Context, s *Scan) error
}

// EventKind describes an agent's execution lifecycle.
type EventKind string

const (
	Started  EventKind = "started"
	Progress EventKind = "progress"
	Finished EventKind = "finished"
	Failed   EventKind = "failed"
)

// Event reports agent activity within a scan.
type Event struct {
	Time    time.Time `json:"time"`
	ScanID  string    `json:"scan_id"`
	Agent   string    `json:"agent"`
	Kind    EventKind `json:"kind"`
	Message string    `json:"message"`
}

// Sink receives execution events synchronously.
type Sink interface{ Emit(Event) }

// NopSink discards all events.
type NopSink struct{}

// Emit discards e.
func (NopSink) Emit(e Event) {}

// RunSequential runs agents in order, stopping on error or cancellation. A nil
// sink discards events. Cancellation during a running agent emits failed.
func RunSequential(ctx context.Context, scan *Scan, sink Sink, agents ...Agent) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("run sequential: %w", err)
	}
	if scan == nil {
		return fmt.Errorf("run sequential: nil scan")
	}
	if sink == nil {
		sink = NopSink{}
	}
	for _, agent := range agents {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("run sequential: %w", err)
		}
		if agent == nil {
			return fmt.Errorf("run sequential: nil agent")
		}
		name := agent.Name()
		emit := func(kind EventKind, message string) {
			sink.Emit(Event{Time: time.Now().UTC(), ScanID: scan.ID, Agent: name, Kind: kind, Message: message})
		}
		emit(Started, "")
		err := ctx.Err()
		if err == nil {
			err = agent.Run(ctx, scan)
		}
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			emit(Failed, err.Error())
			return fmt.Errorf("agent %q: %w", name, err)
		}
		emit(Finished, "")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("run sequential: %w", err)
	}
	return nil
}
