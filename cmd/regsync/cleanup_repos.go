package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/types/ref"
)

// hubRepoAPI is the subset of Docker Hub operations needed for cleanupRepos.
type hubRepoAPI interface {
	listRepositories(ctx context.Context, namespace string) ([]string, error)
	deleteRepository(ctx context.Context, namespace, name string) error
}

// targetNamespace groups wanted repositories under a registry host + namespace.
type targetNamespace struct {
	registry  string // e.g. docker.io
	namespace string // e.g. hostingmaloonde
	wanted    map[string]struct{}
}

// collectWantedTargetNamespaces builds the set of repositories referenced by sync targets,
// grouped by registry host and Hub/org namespace (first path component of the repository).
func collectWantedTargetNamespaces(syncEntries []ConfigSync) (map[string]*targetNamespace, error) {
	out := map[string]*targetNamespace{}
	for _, s := range syncEntries {
		if s.Target == "" {
			continue
		}
		r, err := ref.New(s.Target)
		if err != nil {
			return nil, fmt.Errorf("parse target %q: %w", s.Target, err)
		}
		if r.Scheme != "reg" || r.Repository == "" {
			continue
		}
		nsName, repoName, ok := splitNamespaceRepo(r.Repository)
		if !ok {
			continue
		}
		key := r.Registry + "/" + nsName
		tn, ok := out[key]
		if !ok {
			tn = &targetNamespace{
				registry:  r.Registry,
				namespace: nsName,
				wanted:    map[string]struct{}{},
			}
			out[key] = tn
		}
		tn.wanted[repoName] = struct{}{}
	}
	return out, nil
}

func splitNamespaceRepo(repository string) (namespace, name string, ok bool) {
	parts := strings.Split(repository, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], strings.Join(parts[1:], "/"), true
}

// selectOrphanRepos returns repository short names present in the registry that are not
// in the wanted set and do not match any cleanupReposExclude pattern.
func selectOrphanRepos(present []string, wanted map[string]struct{}, namespace string, excludePatterns []string) ([]string, error) {
	orphans := []string{}
	for _, name := range present {
		if _, ok := wanted[name]; ok {
			continue
		}
		full := namespace + "/" + name
		excluded, _, err := matchesExclusionPattern(name, excludePatterns)
		if err != nil {
			return nil, err
		}
		if !excluded {
			excluded, _, err = matchesExclusionPattern(full, excludePatterns)
			if err != nil {
				return nil, err
			}
		}
		if excluded {
			continue
		}
		orphans = append(orphans, name)
	}
	return orphans, nil
}

func (opts *rootOpts) dockerHubCreds() (user, pass string, err error) {
	for _, host := range opts.conf.Creds {
		name := host.Name
		if name == config.DockerRegistry || name == config.DockerRegistryDNS || name == config.DockerRegistryAuth || name == "index.docker.io" {
			cred := host.GetCred()
			if cred.User != "" && (cred.Password != "" || cred.Token != "") {
				pass = cred.Password
				if pass == "" {
					pass = cred.Token
				}
				return cred.User, pass, nil
			}
		}
	}
	return "", "", fmt.Errorf("no Docker Hub credentials found in config creds for docker.io")
}

func (opts *rootOpts) newHubClient() (hubRepoAPI, error) {
	user, pass, err := opts.dockerHubCreds()
	if err != nil {
		return nil, err
	}
	ua := opts.conf.Defaults.UserAgent
	if ua == "" {
		ua = UserAgent
	}
	return newDockerHubClient(user, pass, ua), nil
}

// runCleanupRepos deletes (or reports) target-namespace repositories that have no dedicated sync entry.
// dryRun=true only logs what would be deleted (used by regsync check).
func (opts *rootOpts) runCleanupRepos(ctx context.Context, dryRun bool) error {
	if opts.conf.Defaults.CleanupRepos == nil || !*opts.conf.Defaults.CleanupRepos {
		opts.log.Debug("cleanupRepos disabled")
		return nil
	}

	namespaces, err := collectWantedTargetNamespaces(opts.conf.Sync)
	if err != nil {
		return err
	}
	if len(namespaces) == 0 {
		opts.log.Debug("No target namespaces found for cleanupRepos")
		return nil
	}

	var errs []error
	for _, tn := range namespaces {
		select {
		case <-ctx.Done():
			errs = append(errs, ErrCanceled)
			return errors.Join(errs...)
		default:
		}

		if tn.registry != config.DockerRegistry && tn.registry != config.DockerRegistryDNS {
			opts.log.Warn("cleanupRepos currently only supports Docker Hub, skipping namespace",
				slog.String("registry", tn.registry),
				slog.String("namespace", tn.namespace))
			continue
		}

		var hub hubRepoAPI
		if opts.hubClient != nil {
			hub = opts.hubClient
		} else {
			var err error
			hub, err = opts.newHubClient()
			if err != nil {
				opts.log.Error("Failed creating Docker Hub client for cleanupRepos",
					slog.String("error", err.Error()))
				errs = append(errs, err)
				continue
			}
		}

		if err := opts.cleanupReposNamespace(ctx, hub, tn, dryRun); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (opts *rootOpts) cleanupReposNamespace(ctx context.Context, hub hubRepoAPI, tn *targetNamespace, dryRun bool) error {
	opts.log.Info("Running cleanupRepos",
		slog.String("registry", tn.registry),
		slog.String("namespace", tn.namespace),
		slog.Int("wanted", len(tn.wanted)),
		slog.Bool("dryRun", dryRun))

	present, err := hub.listRepositories(ctx, tn.namespace)
	if err != nil {
		opts.log.Error("Failed listing repositories for cleanupRepos",
			slog.String("namespace", tn.namespace),
			slog.String("error", err.Error()))
		return err
	}

	orphans, err := selectOrphanRepos(present, tn.wanted, tn.namespace, opts.conf.Defaults.CleanupReposExclude)
	if err != nil {
		return err
	}
	if len(orphans) == 0 {
		opts.log.Debug("No orphan repositories for cleanupRepos",
			slog.String("namespace", tn.namespace))
		return nil
	}

	var errs []error
	for _, name := range orphans {
		select {
		case <-ctx.Done():
			errs = append(errs, ErrCanceled)
			return errors.Join(errs...)
		default:
		}
		full := tn.namespace + "/" + name
		if dryRun {
			opts.log.Info("Would delete repository",
				slog.String("repository", full))
			continue
		}
		opts.log.Info("Deleting repository",
			slog.String("repository", full))
		if err := hub.deleteRepository(ctx, tn.namespace, name); err != nil {
			opts.log.Error("Failed deleting repository",
				slog.String("repository", full),
				slog.String("error", err.Error()))
			errs = append(errs, fmt.Errorf("delete %s: %w", full, err))
			continue
		}
		opts.log.Debug("Deleted repository",
			slog.String("repository", full))
	}
	return errors.Join(errs...)
}
