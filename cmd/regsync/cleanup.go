package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/ref"
)

// Cleanup logic for multiple sync entries with the same target:
// When multiple sync entries share the same target repository, the cleanup
// process considers the combined filter conditions from all entries.
// A tag is only deleted if it doesn't match ANY of the sync entry filters
// and doesn't match ANY of the exclusion patterns from all entries.
// This ensures tags wanted by any sync entry are preserved.

// matchesExclusionPattern checks if a tag matches any exclusion pattern.
// Returns true if the tag matches, along with the matching pattern for logging.
// Returns an error if any regex pattern fails to compile.
func matchesExclusionPattern(tag string, patterns []string) (bool, string, error) {
	if len(patterns) == 0 {
		return false, "", nil
	}

	// Check each pattern
	for _, pattern := range patterns {
		exp, err := regexp.Compile(pattern)
		if err != nil {
			return false, "", fmt.Errorf("invalid exclusion pattern %q: %w", pattern, err)
		}
		if exp.MatchString(tag) {
			return true, pattern, nil
		}
	}

	return false, "", nil
}

// findSyncEntriesForTarget returns all sync entries that have the same target
func (opts *rootOpts) findSyncEntriesForTarget(tgt string) []ConfigSync {
	var entries []ConfigSync
	for _, sync := range opts.conf.Sync {
		if sync.Target == tgt {
			entries = append(entries, sync)
		}
	}
	return entries
}

// digestTagRe matches cosign-style digest tags of the form "<alg>-<hex>.(att|sig)",
// e.g. "sha256-abc123.sig" or "sha256-abc123.att".
var digestTagRe = regexp.MustCompile(`^([a-z0-9]+)-([0-9a-f]+)\.(att|sig)$`)

// isOrphanedDigestTag returns true when tag is a cosign-style .att or .sig tag
// whose referenced image digest is no longer present in the repository.
// It returns false (never orphaned) when the digest still resolves, and an
// error only for unexpected failures.
func isOrphanedDigestTag(ctx context.Context, rc *regclient.RegClient, tgtRef ref.Ref, tag string) (bool, error) {
	m := digestTagRe.FindStringSubmatch(tag)
	if m == nil {
		// Not a digest tag at all – leave it to normal cleanup logic.
		return false, nil
	}
	// Reconstruct the digest: replace the first "-" separator with ":".
	// m[1] = algorithm (e.g. "sha256"), m[2] = hex, m[3] = "att" or "sig".
	digestStr := m[1] + ":" + m[2]
	digestRef := tgtRef.SetTag("").SetDigest(digestStr)
	_, err := rc.ManifestHead(ctx, digestRef)
	if err == nil {
		// Digest still exists – not orphaned.
		return false, nil
	}
	if errors.Is(err, errs.ErrNotFound) || strings.Contains(err.Error(), "404") {
		return true, nil
	}
	return false, err
}

// cleanupTags removes tags from target repository that don't match filters
// It considers all sync entries with the same target to avoid deleting tags
// that are wanted by any of the sync entries
func (opts *rootOpts) cleanupTags(ctx context.Context, s ConfigSync, tgt string) error {
	// Parse target reference
	tgtRef, err := ref.New(tgt)
	if err != nil {
		opts.log.Error("Failed parsing target for cleanup",
			slog.String("target", tgt),
			slog.String("error", err.Error()))
		return err
	}

	// Retrieve all tags from target repository
	tTags, err := opts.rc.TagList(ctx, tgtRef)
	if err != nil {
		opts.log.Error("Failed getting target tags for cleanup",
			slog.String("target", tgtRef.CommonName()),
			slog.String("error", err.Error()))
		return err
	}
	tTagsList, err := tTags.GetTags()
	if err != nil {
		opts.log.Error("Failed getting target tags for cleanup",
			slog.String("target", tgtRef.CommonName()),
			slog.String("error", err.Error()))
		return err
	}

	// Find all sync entries with the same target
	syncEntries := opts.findSyncEntriesForTarget(tgt)
	if len(syncEntries) > 1 {
		opts.log.Debug("Multiple sync entries found for target",
			slog.String("target", tgtRef.CommonName()),
			slog.Int("count", len(syncEntries)))
	}

	// Build list of "wanted" tags from all sync entries with this target
	wantedTags := []string{}
	allSetsEmpty := true

	for _, syncEntry := range syncEntries {
		sets := syncEntry.TagSets
		if len(syncEntry.Tags.Allow) > 0 || len(syncEntry.Tags.Deny) > 0 || len(syncEntry.Tags.SemverRange) > 0 {
			sets = append(sets, syncEntry.Tags)
		}

		if len(sets) > 0 {
			allSetsEmpty = false
			for _, set := range sets {
				filteredCur, err := filterTagList(set, tTagsList)
				if err != nil {
					opts.log.Error("Failed processing tag filters for cleanup",
						slog.String("target", tgtRef.CommonName()),
						slog.Any("allow", set.Allow),
						slog.Any("deny", set.Deny),
						slog.Any("semverRange", set.SemverRange),
						slog.String("error", err.Error()))
					return err
				}
				// Add unique tags to wanted list
				for _, tag := range filteredCur {
					if !slices.Contains(wantedTags, tag) {
						wantedTags = append(wantedTags, tag)
					}
				}
			}
		}
	}

	// If all sync entries have no filters, all tags are wanted
	if allSetsEmpty {
		wantedTags = tTagsList
	}

	// Collect all exclusion patterns from all sync entries with this target
	allExclusionPatterns := []string{}
	for _, syncEntry := range syncEntries {
		allExclusionPatterns = append(allExclusionPatterns, syncEntry.CleanupTagsExclude...)
	}

	// Identify tags to delete
	tagsToDelete := []string{}
	for _, tag := range tTagsList {
		// Check if tag is wanted (matches filters from any sync entry)
		if slices.Contains(wantedTags, tag) {
			// Even wanted tags should be cleaned up if they are orphaned .att/.sig tags.
			orphaned, oErr := isOrphanedDigestTag(ctx, opts.rc, tgtRef, tag)
			if oErr != nil {
				opts.log.Error("Failed checking orphaned digest tag",
					slog.String("target", tgtRef.CommonName()),
					slog.String("tag", tag),
					slog.String("error", oErr.Error()))
				return oErr
			}
			if !orphaned {
				continue
			}
			opts.log.Debug("Orphaned digest tag removed despite being in wanted list",
				slog.String("target", tgtRef.CommonName()),
				slog.String("tag", tag))
			tagsToDelete = append(tagsToDelete, tag)
			continue
		}

		// Check if tag matches exclusion patterns from any sync entry
		excluded, pattern, err := matchesExclusionPattern(tag, allExclusionPatterns)
		if err != nil {
			opts.log.Error("Failed checking exclusion pattern",
				slog.String("target", tgtRef.CommonName()),
				slog.String("tag", tag),
				slog.String("error", err.Error()))
			return err
		}
		if excluded {
			// Even if the tag matches an exclusion pattern, remove it when it is an
			// orphaned .att/.sig tag (its referenced image digest is gone).
			orphaned, oErr := isOrphanedDigestTag(ctx, opts.rc, tgtRef, tag)
			if oErr != nil {
				opts.log.Error("Failed checking orphaned digest tag",
					slog.String("target", tgtRef.CommonName()),
					slog.String("tag", tag),
					slog.String("error", oErr.Error()))
				return oErr
			}
			if !orphaned {
				opts.log.Debug("Tag excluded from cleanup",
					slog.String("target", tgtRef.CommonName()),
					slog.String("tag", tag),
					slog.String("pattern", pattern))
				continue
			}
			opts.log.Debug("Orphaned digest tag overrides exclusion pattern",
				slog.String("target", tgtRef.CommonName()),
				slog.String("tag", tag),
				slog.String("pattern", pattern))
		}

		// Tag should be deleted
		tagsToDelete = append(tagsToDelete, tag)
	}

	// Delete unwanted tags
	errs := []error{}
	for _, tag := range tagsToDelete {
		// Check context before each deletion
		select {
		case <-ctx.Done():
			errs = append(errs, ErrCanceled)
			return errors.Join(errs...)
		default:
		}

		opts.log.Info("Deleting tag",
			slog.String("target", tgtRef.CommonName()),
			slog.String("tag", tag))

		tagRef := tgtRef.SetTag(tag)
		err := opts.rc.TagDelete(ctx, tagRef)
		if err != nil {
			opts.log.Error("Failed to delete tag",
				slog.String("target", tgtRef.CommonName()),
				slog.String("tag", tag),
				slog.String("error", err.Error()))
			errs = append(errs, fmt.Errorf("failed to delete tag %s:%s: %w", tgtRef.CommonName(), tag, err))
		} else {
			opts.log.Debug("Deleted tag",
				slog.String("target", tgtRef.CommonName()),
				slog.String("tag", tag))
		}
	}

	if len(tagsToDelete) == 0 {
		opts.log.Debug("No tags require cleanup",
			slog.String("target", tgtRef.CommonName()))
	}

	return errors.Join(errs...)
}

// runCleanupForAllTargets performs cleanup on startup for all targets where cleanup is enabled.
// This ensures the repository is in a defined state immediately after configuration changes.
// It deduplicates targets to avoid running cleanup multiple times for targets with multiple sync entries.
func (opts *rootOpts) runCleanupForAllTargets(ctx context.Context) error {
	// Collect unique targets and find at least one sync entry per target where cleanup is enabled
	targetMap := make(map[string]ConfigSync)
	for _, s := range opts.conf.Sync {
		tgt := s.Target
		if tgt == "" {
			continue
		}
		// Only run cleanup if enabled for this sync entry
		if s.CleanupTags != nil && *s.CleanupTags {
			targetMap[tgt] = s
		}
	}

	if len(targetMap) == 0 {
		opts.log.Debug("No targets with cleanup enabled on startup")
		return nil
	}

	opts.log.Info("Running startup cleanup",
		slog.Int("targets", len(targetMap)))

	var errs []error
	for tgt, s := range targetMap {
		// Check context before each cleanup
		select {
		case <-ctx.Done():
			errs = append(errs, ErrCanceled)
			return errors.Join(errs...)
		default:
		}

		opts.log.Debug("Starting cleanup on startup",
			slog.String("target", tgt))
		err := opts.cleanupTags(ctx, s, tgt)
		if err != nil {
			opts.log.Error("Startup cleanup failed",
				slog.String("target", tgt),
				slog.String("error", err.Error()))
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
