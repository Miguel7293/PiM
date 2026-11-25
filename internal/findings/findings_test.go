package findings

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math"
	"os"
	"sync"
	"testing"
)

var update = flag.Bool("update", false, "update findings golden")

func fixture() Finding {
	return Finding{ID: "a", ComponentID: "dependency:npm:lodash@4.17.20", VulnID: "CVE-2021-23337", Agent: "collector", Severity: High, Status: Candidate, Evidence: []Evidence{{Kind: Advisory, Source: "source"}}, Aliases: []string{"alias"}, Techniques: []Technique{{Framework: CWE, ID: "CWE-78"}}}
}

func TestSeverity(t *testing.T) {
	for _, tc := range []struct {
		score float64
		want  Severity
	}{{-1, Unknown}, {math.NaN(), Unknown}, {math.Inf(1), Unknown}, {10.1, Unknown}, {0, None}, {0.1, Low}, {3.9, Low}, {4, Medium}, {6.9, Medium}, {7, High}, {8.9, High}, {9, Critical}, {10, Critical}} {
		if got := SeverityFromCVSS(tc.score); got != tc.want {
			t.Errorf("%v: %s != %s", tc.score, got, tc.want)
		}
	}
}

func TestValidation(t *testing.T) {
	for _, change := range []func(*Finding){
		func(f *Finding) { f.ComponentID = "" }, func(f *Finding) { f.VulnID = "" }, func(f *Finding) { f.Agent = "" },
		func(f *Finding) { f.Severity = "invalid" }, func(f *Finding) { f.Status = "invalid" }, func(f *Finding) { f.Evidence = nil },
		func(f *Finding) { f.Evidence[0].Kind = "invalid" }, func(f *Finding) { f.Techniques[0].Framework = "invalid" },
	} {
		f := fixture()
		change(&f)
		if f.Validate() == nil {
			t.Fatalf("accepted invalid finding: %+v", f)
		}
		var s Set
		if s.Add(f) == nil || len(s.All()) != 0 {
			t.Fatal("invalid addition")
		}
	}
	for _, severity := range []Severity{Unknown, None, Low, Medium, High, Critical} {
		for _, status := range []Status{Candidate, Supported, Unsupported} {
			for _, kind := range []EvidenceKind{Manifest, Advisory, VersionRange, Reachability, Model} {
				for _, framework := range []Framework{CWE, CAPEC, ATTACK, OWASP} {
					f := fixture()
					f.Severity = severity
					f.Status = status
					f.Evidence[0].Kind = kind
					f.Techniques[0].Framework = framework
					if err := f.Validate(); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}

func TestID(t *testing.T) {
	if NewID("a", "bc") != NewID("a", "bc") || len(NewID("a", "bc")) != 32 {
		t.Fatal("unstable ID")
	}
	seen := map[string]bool{}
	for _, pair := range [][2]string{{"a", "bc"}, {"ab", "c"}, {"a\x00", "b"}, {"a", "\x00b"}, {"bc", "a"}} {
		id := NewID(pair[0], pair[1])
		if seen[id] {
			t.Fatal("ambiguous pair")
		}
		seen[id] = true
	}
	var s Set
	f := fixture()
	f.ID = ""
	if err := s.Add(f); err != nil {
		t.Fatal(err)
	}
	if s.All()[0].ID != NewID(f.ComponentID, f.VulnID) {
		t.Fatal("missing derived ID")
	}
}

func TestMergeConcurrentAndCopies(t *testing.T) {
	var s Set
	f := fixture()
	if err := s.Add(f); err != nil {
		t.Fatal(err)
	}
	f.Aliases[0] = "mutated"
	f.Evidence[0].Source = "mutated"
	f.Techniques[0].ID = "mutated"
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := fixture()
			f.Status = Supported
			f.Score.CVSS = 9
			f.Aliases = append(f.Aliases, "other")
			f.Evidence = append(f.Evidence, Evidence{Kind: Model})
			f.Techniques = append(f.Techniques, Technique{Framework: CAPEC})
			if err := s.Add(f); err != nil {
				t.Error(err)
			}
			s.All()
			if _, err := s.MarshalJSON(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got := s.All()[0]
	if len(got.Aliases) != 2 || len(got.Evidence) != 2 || len(got.Techniques) != 2 || got.Status != Candidate || got.Score.CVSS != 0 {
		t.Fatalf("bad merge: %+v", got)
	}
	before, _ := s.MarshalJSON()
	got.Aliases[0] = "changed"
	got.Evidence[0].Source = "changed"
	got.Techniques[0].ID = "changed"
	after, _ := s.MarshalJSON()
	if !bytes.Equal(before, after) {
		t.Fatal("copy leaked")
	}
	var retained *Finding
	if err := s.Update("a", func(f *Finding) { f.Status = Supported; f.Score.CVSS = 8; retained = f }); err != nil {
		t.Fatal(err)
	}
	retained.Evidence[0].Source = "leaked"
	if s.All()[0].Status != Supported || s.All()[0].Score.CVSS != 8 || s.All()[0].Evidence[0].Source == "leaked" {
		t.Fatal("update/copy failure")
	}
	before, _ = s.MarshalJSON()
	for _, change := range []func(*Finding){nil, func(f *Finding) { f.ID = "new" }, func(f *Finding) { f.Status = "bad"; f.Evidence[0].Source = "bad" }} {
		if s.Update("a", change) == nil {
			t.Fatal("accepted invalid update")
		}
	}
	if s.Update("missing", func(*Finding) {}) == nil {
		t.Fatal("updated absent ID")
	}
	after, _ = s.MarshalJSON()
	if !bytes.Equal(before, after) {
		t.Fatal("failed update mutated set")
	}
}

func TestCanonicalJSON(t *testing.T) {
	build := func(reverse bool) *Set {
		s := &Set{}
		a := fixture()
		b := fixture()
		b.ID = "b"
		b.Evidence = append(b.Evidence, Evidence{Kind: Model, Detail: "model claim"})
		b.Aliases = []string{"z", "a", "z"}
		items := []Finding{a, b}
		if reverse {
			items[0], items[1] = items[1], items[0]
			b.Aliases = []string{"a", "z"}
			items[0] = b
		}
		for _, f := range items {
			if err := s.Add(f); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	s := build(false)
	data, err := s.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	other, err := build(true).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, other) || !bytes.Equal(data, buf.Bytes()) {
		t.Fatal("noncanonical JSON")
	}
	if compact, err := json.Marshal(s); err != nil || !json.Valid(compact) {
		t.Fatalf("marshal: %v", err)
	}
	path := "testdata/findings.golden.json"
	if *update {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("golden mismatch:\n%s", data)
	}
}

type brokenWriter struct{ err error }

func (w brokenWriter) Write(p []byte) (int, error) { return 0, w.err }

func TestJSONErrorsAndEmpty(t *testing.T) {
	var s Set
	data, err := s.MarshalJSON()
	if err != nil || string(data) != "{\n  \"findings\": []\n}\n" {
		t.Fatalf("empty: %s %v", data, err)
	}
	failure := errors.New("failure")
	if !errors.Is(s.WriteJSON(brokenWriter{failure}), failure) {
		t.Fatal("lost writer error")
	}
	if !errors.Is(s.WriteJSON(brokenWriter{}), io.ErrShortWrite) {
		t.Fatal("lost short write")
	}
	f := fixture()
	f.Score.CVSS = math.NaN()
	if err := s.Add(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarshalJSON(); err == nil {
		t.Fatal("missing marshal error")
	}
	if s.WriteJSON(io.Discard) == nil {
		t.Fatal("missing write marshal error")
	}
}
