package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/regclient/regclient/config"
)

func TestSelectOrphanRepos(t *testing.T) {
	t.Parallel()
	wanted := map[string]struct{}{
		"alpine": {},
		"nginx":  {},
	}
	present := []string{"alpine", "nginx", "redis", "daimoniac_regsync", "old-repo"}

	orphans, err := selectOrphanRepos(present, wanted, "hostingmaloonde", []string{"daimoniac_regsync"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expect := []string{"redis", "old-repo"}
	if !reflect.DeepEqual(orphans, expect) {
		t.Errorf("orphans = %v, want %v", orphans, expect)
	}

	// exclude by full path pattern
	orphans, err = selectOrphanRepos(present, wanted, "hostingmaloonde", []string{"^hostingmaloonde/redis$"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expect = []string{"daimoniac_regsync", "old-repo"}
	if !reflect.DeepEqual(orphans, expect) {
		t.Errorf("orphans = %v, want %v", orphans, expect)
	}
}

func TestCollectWantedTargetNamespaces(t *testing.T) {
	t.Parallel()
	syncEntries := []ConfigSync{
		{Target: "hostingmaloonde/alpine", Type: "repository"},
		{Target: "hostingmaloonde/busybox:1.37.0", Type: "image"},
		{Target: "hostingmaloonde/alpine", Type: "repository"}, // duplicate repo
		{Target: "registry:5000/other/repo", Type: "repository"},
	}
	got, err := collectWantedTargetNamespaces(syncEntries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hubKey := "docker.io/hostingmaloonde"
	tn, ok := got[hubKey]
	if !ok {
		t.Fatalf("missing hub namespace key %q in %v", hubKey, keysOf(got))
	}
	if _, ok := tn.wanted["alpine"]; !ok {
		t.Errorf("expected alpine in wanted")
	}
	if _, ok := tn.wanted["busybox"]; !ok {
		t.Errorf("expected busybox in wanted")
	}
	otherKey := "registry:5000/other"
	if _, ok := got[otherKey]; !ok {
		t.Errorf("missing other namespace key %q", otherKey)
	}
}

func keysOf(m map[string]*targetNamespace) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type fakeHub struct {
	mu        sync.Mutex
	repos     map[string][]string
	deleted   []string
	listErr   error
	deleteErr error
}

func (f *fakeHub) listRepositories(ctx context.Context, namespace string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.repos[namespace]...), nil
}

func (f *fakeHub) deleteRepository(ctx context.Context, namespace, name string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, namespace+"/"+name)
	remaining := []string{}
	for _, r := range f.repos[namespace] {
		if r != name {
			remaining = append(remaining, r)
		}
	}
	f.repos[namespace] = remaining
	return nil
}

func TestRunCleanupRepos(t *testing.T) {
	t.Parallel()
	bTrue := true
	bFalse := false
	hub := &fakeHub{
		repos: map[string][]string{
			"hostingmaloonde": {"alpine", "nginx", "redis", "daimoniac_regsync"},
		},
	}
	opts := &rootOpts{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		conf: &Config{
			Defaults: ConfigDefaults{
				CleanupRepos:        &bTrue,
				CleanupReposExclude: []string{"daimoniac_regsync"},
			},
			Sync: []ConfigSync{
				{Target: "hostingmaloonde/alpine", Type: "repository"},
				{Target: "hostingmaloonde/nginx:1.27", Type: "image"},
			},
			Creds: []config.Host{{Name: "docker.io", User: "u", Pass: "p"}},
		},
		hubClient: hub,
	}

	if err := opts.runCleanupRepos(context.Background(), false); err != nil {
		t.Fatalf("runCleanupRepos: %v", err)
	}
	expectDeleted := []string{"hostingmaloonde/redis"}
	if !reflect.DeepEqual(hub.deleted, expectDeleted) {
		t.Errorf("deleted = %v, want %v", hub.deleted, expectDeleted)
	}

	// dry-run should not delete
	hub2 := &fakeHub{
		repos: map[string][]string{
			"hostingmaloonde": {"alpine", "orphan"},
		},
	}
	opts.hubClient = hub2
	opts.conf.Defaults.CleanupReposExclude = nil
	if err := opts.runCleanupRepos(context.Background(), true); err != nil {
		t.Fatalf("dry-run cleanupRepos: %v", err)
	}
	if len(hub2.deleted) != 0 {
		t.Errorf("dry-run deleted = %v, want none", hub2.deleted)
	}

	// disabled is a no-op
	opts.conf.Defaults.CleanupRepos = &bFalse
	opts.hubClient = hub2
	if err := opts.runCleanupRepos(context.Background(), false); err != nil {
		t.Fatalf("disabled cleanupRepos: %v", err)
	}
	if len(hub2.deleted) != 0 {
		t.Errorf("disabled deleted = %v, want none", hub2.deleted)
	}
}

func TestConfigCleanupReposParsing(t *testing.T) {
	t.Parallel()
	yaml := `
version: 1
creds:
  - registry: docker.io
    user: test
    pass: secret
defaults:
  cleanupRepos: true
  cleanupReposExclude:
    - "daimoniac_regsync"
  cleanupReposSchedule: "15 5 * * *"
sync:
  - source: alpine
    target: hostingmaloonde/alpine
    type: repository
`
	c, err := ConfigLoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("ConfigLoadReader: %v", err)
	}
	if c.Defaults.CleanupRepos == nil || !*c.Defaults.CleanupRepos {
		t.Fatalf("CleanupRepos = %v, want true", c.Defaults.CleanupRepos)
	}
	if c.Defaults.CleanupReposSchedule != "15 5 * * *" {
		t.Errorf("CleanupReposSchedule = %q, want %q", c.Defaults.CleanupReposSchedule, "15 5 * * *")
	}
	if !reflect.DeepEqual(c.Defaults.CleanupReposExclude, []string{"daimoniac_regsync"}) {
		t.Errorf("CleanupReposExclude = %v", c.Defaults.CleanupReposExclude)
	}

	// default schedule when enabled without schedule
	yaml2 := `
version: 1
defaults:
  cleanupRepos: true
sync:
  - source: alpine
    target: hostingmaloonde/alpine
    type: repository
`
	c2, err := ConfigLoadReader(strings.NewReader(yaml2))
	if err != nil {
		t.Fatalf("ConfigLoadReader: %v", err)
	}
	if c2.Defaults.CleanupReposSchedule != defaultCleanupReposSchedule {
		t.Errorf("default schedule = %q, want %q", c2.Defaults.CleanupReposSchedule, defaultCleanupReposSchedule)
	}
}

func TestDockerHubClientListDelete(t *testing.T) {
	t.Parallel()
	var deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/users/login/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
	})
	mux.HandleFunc("/repositories/hostingmaloonde/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(dockerHubRepoListResp{
				Results: []dockerHubRepoEntry{{Name: "alpine"}, {Name: "orphan"}},
			})
		case http.MethodDelete:
			// path: /repositories/hostingmaloonde/orphan/
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(parts) >= 3 {
				deleted = append(deleted, parts[1]+"/"+parts[2])
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newDockerHubClient("user", "pass", "test-agent")
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	repos, err := c.listRepositories(context.Background(), "hostingmaloonde")
	if err != nil {
		t.Fatalf("listRepositories: %v", err)
	}
	if !reflect.DeepEqual(repos, []string{"alpine", "orphan"}) {
		t.Errorf("repos = %v", repos)
	}
	if err := c.deleteRepository(context.Background(), "hostingmaloonde", "orphan"); err != nil {
		t.Fatalf("deleteRepository: %v", err)
	}
	if !reflect.DeepEqual(deleted, []string{"hostingmaloonde/orphan"}) {
		t.Errorf("deleted = %v", deleted)
	}
}
