// Package findings defines the shared, evidence-backed vulnerability contract.
package findings

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
)

// Severity is a CVSS v3 qualitative rating.
type Severity string

const (
	Unknown  Severity = "unknown"
	None     Severity = "none"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// SeverityFromCVSS applies FIRST's CVSS v3 thresholds. Invalid scores return
// Unknown. An explicit zero score means None, unlike an absent Score.CVSS.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case math.IsNaN(score), score < 0, score > 10:
		return Unknown
	case score == 0:
		return None
	case score < 4:
		return Low
	case score < 7:
		return Medium
	case score < 9:
		return High
	default:
		return Critical
	}
}

// Status records whether a verifier has confirmed a collector's evidence.
type Status string

const (
	Candidate   Status = "candidate"
	Supported   Status = "supported"
	Unsupported Status = "unsupported"
)

// EvidenceKind distinguishes source evidence from model-generated claims.
type EvidenceKind string

const (
	Manifest     EvidenceKind = "manifest"
	Advisory     EvidenceKind = "advisory"
	VersionRange EvidenceKind = "version_range"
	Reachability EvidenceKind = "reachability"
	Model        EvidenceKind = "model"
)

// Evidence describes the origin and location of a supporting observation.
type Evidence struct {
	Kind     EvidenceKind `json:"kind"`
	Source   string       `json:"source"`
	Detail   string       `json:"detail"`
	Location string       `json:"location"`
}

// Framework names a recognized security classification system.
type Framework string

const (
	CWE    Framework = "CWE"
	CAPEC  Framework = "CAPEC"
	ATTACK Framework = "ATTACK"
	OWASP  Framework = "OWASP"
)

// Technique identifies a weakness or attack technique within a framework.
type Technique struct {
	Framework Framework `json:"framework"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
}

// Score contains optional prioritization inputs. Zero values mean unknown
// (including KEV=false), and are omitted from JSON.
type Score struct {
	CVSS       float64 `json:"cvss,omitempty"`
	CVSSVector string  `json:"cvss_vector,omitempty"`
	EPSS       float64 `json:"epss,omitempty"`
	KEV        bool    `json:"kev,omitempty"`
	Priority   float64 `json:"priority,omitempty"`
}

// Finding associates a vulnerability and its evidence with a structure node.
type Finding struct {
	ID          string      `json:"id"`
	ComponentID string      `json:"component_id"`
	Ecosystem   string      `json:"ecosystem,omitempty"`
	Package     string      `json:"package,omitempty"`
	Version     string      `json:"version,omitempty"`
	VulnID      string      `json:"vuln_id"`
	Aliases     []string    `json:"aliases,omitempty"`
	Summary     string      `json:"summary,omitempty"`
	Severity    Severity    `json:"severity"`
	Score       Score       `json:"score"`
	Techniques  []Technique `json:"techniques,omitempty"`
	Evidence    []Evidence  `json:"evidence"`
	Status      Status      `json:"status"`
	Agent       string      `json:"agent"`
}

// NewID hashes an unambiguous pair into a stable 128-bit hexadecimal identifier.
func NewID(componentID, vulnID string) string {
	data, _ := json.Marshal([2]string{componentID, vulnID})
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:16])
}

// Validate requires identifying fields, evidence, and explicitly valid enums.
func (f Finding) Validate() error {
	if f.ComponentID == "" || f.VulnID == "" || f.Agent == "" {
		return fmt.Errorf("finding: component ID, vulnerability ID and agent are required")
	}
	switch f.Severity {
	case Unknown, None, Low, Medium, High, Critical:
	default:
		return fmt.Errorf("finding: invalid severity %q", f.Severity)
	}
	switch f.Status {
	case Candidate, Supported, Unsupported:
	default:
		return fmt.Errorf("finding: invalid status %q", f.Status)
	}
	if len(f.Evidence) == 0 {
		return fmt.Errorf("finding: evidence is required")
	}
	for _, e := range f.Evidence {
		switch e.Kind {
		case Manifest, Advisory, VersionRange, Reachability, Model:
		default:
			return fmt.Errorf("finding: invalid evidence kind %q", e.Kind)
		}
	}
	for _, t := range f.Techniques {
		switch t.Framework {
		case CWE, CAPEC, ATTACK, OWASP:
		default:
			return fmt.Errorf("finding: invalid framework %q", t.Framework)
		}
	}
	return nil
}
