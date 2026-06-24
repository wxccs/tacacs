// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Daniel Wu.

package yang

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/wxccs/tacacs/types"
)

// watchDebounce is the interval at which rapid successive write events
// (e.g. from an editor's atomic save) are coalesced into a single reload.
const watchDebounce = time.Second

// Watch monitors the file at path for changes and reloads it via Load,
// sending each successfully parsed *Config to the returned channel. A
// parse failure is logged via l and the previous config is kept (no
// value is sent). The channel is closed when ctx is cancelled.
//
// Watch creates a fsnotify watcher on the directory containing path and
// filters events by basename, so renaming the file or its directory is
// not handled.
//
// The returned channel is buffered (size 1); a slow consumer that does
// not drain the channel will cause the most recent config to be dropped
// on the floor, which is the desired behavior under backpressure.
func Watch(ctx context.Context, path string, l types.Logger) (<-chan *Config, error) {
	ch := make(chan *Config, 1)
	cb := func(path string) error {
		cfg, err := Load(path)
		if err != nil {
			return err
		}
		select {
		case ch <- cfg:
		default:
			if l != nil {
				l.Warn("tacacs: config channel full; dropping update",
					"func", "yang.Watch",
				)
			}
		}
		return nil
	}
	if err := WatchFile(ctx, path, l, cb); err != nil {
		return nil, err
	}
	return ch, nil
}

// WatchFile watches path for changes and invokes fn on the initial load
// and each subsequent (debounced) modification. fn receives the path so it
// can re-load using any decoder (e.g. server.LoadUserConfig rather than
// yang.Load); an error from fn is logged via l and the previous state is
// kept, so a transient parse failure does not clear the caller's view of
// the config.
//
// WatchFile creates an fsnotify watcher on the directory containing path
// and filters events by basename, so renaming the file or its directory is
// not handled. The watcher and goroutine run until ctx is cancelled.
func WatchFile(ctx context.Context, path string, l types.Logger, fn func(path string) error) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(filepath.Dir(path)); err != nil {
		_ = w.Close()
		return err
	}
	// Initial load so callers get the current state immediately.
	if err := fn(path); err != nil {
		if l != nil {
			l.Warn("tacacs: initial config load failed",
				"func", "yang.WatchFile",
				"path", path,
				"err", err.Error(),
			)
		}
	}
	go watchFileLoop(ctx, w, path, fn, l)
	return nil
}

func watchFileLoop(ctx context.Context, w *fsnotify.Watcher, path string, fn func(path string) error, l types.Logger) {
	base := filepath.Base(path)
	var (
		pending bool
		mu      sync.Mutex
		ticker  = time.NewTicker(watchDebounce)
	)
	defer ticker.Stop()
	defer w.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			// Only consider events on our target basename. fsnotify
			// reports events on every file in the watched directory; an
			// editor's swap file (e.g. ".swp") would otherwise trigger
			// spurious reloads.
			if filepath.Base(ev.Name) != base {
				continue
			}
			mu.Lock()
			pending = true
			mu.Unlock()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			if l != nil {
				l.Warn("tacacs: fsnotify error",
					"func", "yang.WatchFile",
					"err", err.Error(),
				)
			}
		case <-ticker.C:
			mu.Lock()
			fire := pending
			pending = false
			mu.Unlock()
			if !fire {
				continue
			}
			if err := fn(path); err != nil {
				if l != nil {
					l.Warn("tacacs: config reload failed; keeping previous",
						"func", "yang.WatchFile",
						"path", path,
						"err", err.Error(),
					)
				}
				continue
			}
			if l != nil {
				l.Info("tacacs: config reloaded",
					"func", "yang.WatchFile",
					"path", path,
				)
			}
		}
	}
}
