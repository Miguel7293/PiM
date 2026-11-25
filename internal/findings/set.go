package findings

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
)

// Set is a concurrent collection. Its zero value is ready for use; do not copy
// it after first use. Inputs and returned findings are defensively copied.
type Set struct {
	mu    sync.RWMutex
	items map[string]Finding
}

func canonical[T comparable](values []T) []T {
	result := make([]T, 0, len(values))
	seen := make(map[T]bool)
	for _, v := range values {
		if !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, _ := json.Marshal(result[i])
		b, _ := json.Marshal(result[j])
		return string(a) < string(b)
	})
	return result
}

func clone(f Finding) Finding {
	f.Aliases = canonical(f.Aliases)
	f.Evidence = canonical(f.Evidence)
	f.Techniques = canonical(f.Techniques)
	return f
}

// Add validates f and derives an ID when absent. Duplicate IDs merge only
// evidence, aliases and techniques, retaining the original scalar fields.
func (s *Set) Add(f Finding) error {
	if err := f.Validate(); err != nil {
		return fmt.Errorf("add finding: %w", err)
	}
	if f.ID == "" {
		f.ID = NewID(f.ComponentID, f.VulnID)
	}
	f = clone(f)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]Finding)
	}
	if old, ok := s.items[f.ID]; ok {
		old.Evidence = append(old.Evidence, f.Evidence...)
		old.Aliases = append(old.Aliases, f.Aliases...)
		old.Techniques = append(old.Techniques, f.Techniques...)
		f = clone(old)
	}
	s.items[f.ID] = f
	return nil
}

// Update atomically validates and commits a change to a copy. The callback must
// not call methods on this Set. IDs cannot be changed; failed updates roll back.
func (s *Set) Update(id string, update func(*Finding)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.items[id]
	if !ok {
		return fmt.Errorf("update finding %q: not found", id)
	}
	if update == nil {
		return fmt.Errorf("update finding %q: nil callback", id)
	}
	f = clone(f)
	update(&f)
	if f.ID != id {
		return fmt.Errorf("update finding %q: ID cannot change", id)
	}
	if err := f.Validate(); err != nil {
		return fmt.Errorf("update finding %q: %w", id, err)
	}
	s.items[id] = clone(f)
	return nil
}

// All returns independent copies sorted by ID, with canonical collection order.
func (s *Set) All() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Finding, 0, len(s.items))
	for _, f := range s.items {
		result = append(result, clone(f))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// MarshalJSON returns two-space-indented JSON with a trailing newline, matching
// graph's convention. json.Marshal compacts these canonical bytes.
func (s *Set) MarshalJSON() ([]byte, error) {
	data, err := json.MarshalIndent(struct {
		Findings []Finding `json:"findings"`
	}{s.All()}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteJSON writes canonical JSON to w.
func (s *Set) WriteJSON(w io.Writer) error {
	data, err := s.MarshalJSON()
	if err != nil {
		return err
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("write findings: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write findings: %w", io.ErrShortWrite)
	}
	return nil
}
