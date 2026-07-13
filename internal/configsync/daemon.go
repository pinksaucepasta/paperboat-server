package configsync

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

func (e *Engine) RunDaemon(ctx context.Context) error {
	if existing, err := ReadStatus(e.StatusPath(), e.cfg.Policy.SummaryLimit); err == nil && existing != nil {
		e.status.last = *existing
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		e.recordError("watcher_init_failed", err)
		return err
	}
	defer watcher.Close()
	if err := e.registerDirectories(watcher); err != nil {
		e.recordError("watcher_registration_failed", err)
		return err
	}
	if err := e.status.write(func(status *Status) {
		if status.State == "error" && status.ErrorCode != "watcher_error" && status.ErrorCode != "watcher_registration_failed" {
			return
		}
		status.State = stateForResult(status.Skipped, status.Conflicts, status.PendingPathCount, "watching")
		status.ErrorCode, status.ErrorMessage = "", ""
	}); err != nil {
		return err
	}
	quiet := time.NewTimer(time.Hour)
	if !quiet.Stop() {
		<-quiet.C
	}
	poll := time.NewTicker(e.cfg.Policy.RemotePollInterval)
	defer poll.Stop()
	force := time.NewTicker(minDuration(time.Second, e.cfg.Policy.MaxDirtyDelay))
	defer force.Stop()
	var dirtySince time.Time
	lastEvent := time.Time{}
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), e.cfg.Policy.ShutdownFlushTimeout)
			err := e.Flush(flushCtx, "shutdown")
			cancel()
			if err != nil {
				return fmt.Errorf("shutdown config flush: %w", err)
			}
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return errors.New("config watcher event channel closed")
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			lastEvent = e.cfg.Now()
			if dirtySince.IsZero() {
				dirtySince = lastEvent
			}
			e.recordPendingHint()
			if event.Op&fsnotify.Create != 0 {
				e.recordWatcherRegistrationError(e.registerDirectories(watcher))
			}
			if !quiet.Stop() {
				select {
				case <-quiet.C:
				default:
				}
			}
			quiet.Reset(e.cfg.Policy.Debounce)
		case watchErr, ok := <-watcher.Errors:
			if !ok {
				return errors.New("config watcher error channel closed")
			}
			lastEvent = e.cfg.Now()
			if dirtySince.IsZero() {
				dirtySince = lastEvent
			}
			_ = e.status.write(func(status *Status) {
				status.State = "warning"
				status.ErrorCode = "watcher_error"
				status.ErrorMessage = watchErr.Error()
			})
			e.recordWatcherRegistrationError(e.registerDirectories(watcher))
			if !quiet.Stop() {
				select {
				case <-quiet.C:
				default:
				}
			}
			quiet.Reset(e.cfg.Policy.Debounce)
		case <-quiet.C:
			if dirtySince.IsZero() {
				continue
			}
			if e.cfg.Now().Sub(e.lastPush) < e.cfg.Policy.MinPushInterval && e.cfg.Now().Sub(dirtySince) < e.cfg.Policy.MaxDirtyDelay {
				quiet.Reset(e.cfg.Policy.MinPushInterval - e.cfg.Now().Sub(e.lastPush))
				continue
			}
			if err := e.Sync(ctx, "watch"); err == nil {
				drainWatcherEvents(watcher)
				if pending, pendingErr := e.hasFlushablePending(); pendingErr != nil {
					return pendingErr
				} else if pending {
					quiet.Reset(e.cfg.Policy.Debounce)
				} else {
					dirtySince = time.Time{}
				}
			} else {
				quiet.Reset(backoff(e.cfg.Now().Sub(lastEvent)))
			}
		case <-poll.C:
			if dirtySince.IsZero() {
				_ = e.Sync(ctx, "remote")
				drainWatcherEvents(watcher)
			}
		case <-force.C:
			if !dirtySince.IsZero() && e.cfg.Now().Sub(dirtySince) >= e.cfg.Policy.MaxDirtyDelay {
				if err := e.Sync(ctx, "max-delay"); err == nil {
					drainWatcherEvents(watcher)
					if pending, pendingErr := e.hasFlushablePending(); pendingErr != nil {
						return pendingErr
					} else if pending {
						if !quiet.Stop() {
							select {
							case <-quiet.C:
							default:
							}
						}
						quiet.Reset(e.cfg.Policy.Debounce)
					} else {
						dirtySince = time.Time{}
					}
				} else {
					if !quiet.Stop() {
						select {
						case <-quiet.C:
						default:
						}
					}
					quiet.Reset(backoff(e.cfg.Now().Sub(lastEvent)))
				}
			}
		}
	}
}

func (e *Engine) recordPendingHint() {
	_ = e.status.write(func(status *Status) {
		if status.PendingPathCount == 0 {
			status.PendingPathCount = 1
		}
		if status.ErrorCode != "" {
			status.State = "warning"
			return
		}
		status.State = stateForResult(status.Skipped, status.Conflicts, status.PendingPathCount, "pending")
	})
}

func (e *Engine) recordWatcherRegistrationError(err error) {
	if err == nil {
		return
	}
	_ = e.status.write(func(status *Status) {
		status.State = "warning"
		status.ErrorCode = "watcher_registration_failed"
		status.ErrorMessage = err.Error()
	})
}

func drainWatcherEvents(watcher *fsnotify.Watcher) {
	for {
		select {
		case <-watcher.Events:
		default:
			return
		}
	}
}

func (e *Engine) registerDirectories(w *fsnotify.Watcher) error {
	return filepath.WalkDir(e.cfg.Home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(e.cfg.Home, path)
		if err != nil {
			return err
		}
		if rel != "." {
			rel = filepath.ToSlash(rel)
			if e.cfg.Policy.Excluded(rel) || (!e.cfg.Policy.Managed(rel) && !mayContainManaged(rel, e.cfg.Policy)) {
				return filepath.SkipDir
			}
		}
		if err := w.Add(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
}

func backoff(age time.Duration) time.Duration {
	if age < 2*time.Second {
		return 2 * time.Second
	}
	if age > time.Minute {
		return time.Minute
	}
	var jitter [1]byte
	_, _ = rand.Read(jitter[:])
	return age + time.Duration(int64(age)*int64(jitter[0]%26)/100)
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
