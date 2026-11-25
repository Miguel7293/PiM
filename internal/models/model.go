// Package models provides a common interface for remote and local models.
package models

import "context"

type Model interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// FakeModel returns a fixed result without network access.
type FakeModel struct {
	Response string
	Err      error
}

func (m FakeModel) Complete(ctx context.Context, prompt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return m.Response, m.Err
}

var _ Model = FakeModel{}
