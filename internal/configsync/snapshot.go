package configsync

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fileState struct {
	Hash   string      `json:"hash"`
	Bytes  int64       `json:"bytes"`
	Mode   fs.FileMode `json:"mode"`
	Target string      `json:"target,omitempty"`
}

type snapshot struct {
	Files   map[string]fileState
	Skipped []PathSummary
}

var errSourceChanged = errors.New("config source changed during copy")

func takeSnapshot(home string, policy Policy) (snapshot, error) {
	result := snapshot{Files: map[string]fileState{}}
	root, err := os.Stat(home)
	if err != nil {
		return result, fmt.Errorf("stat config home: %w", err)
	}
	if !root.IsDir() {
		return result, errors.New("config home is not a directory")
	}
	err = filepath.WalkDir(home, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk config path %q: %w", relativeForError(home, path), walkErr)
		}
		rel, err := filepath.Rel(home, path)
		if err != nil {
			return fmt.Errorf("resolve config path: %w", err)
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !policy.Managed(rel) {
			if entry.IsDir() && !mayContainManaged(rel, policy) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect config path %q: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := portableSymlink(home, path)
			if err != nil {
				result.Skipped = append(result.Skipped, PathSummary{Path: rel, Reason: "unsafe_symlink"})
				return nil
			}
			result.Files[rel] = fileState{Hash: hashBytes([]byte("symlink:" + target)), Bytes: int64(len(target)), Mode: os.ModeSymlink, Target: target}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			result.Skipped = append(result.Skipped, PathSummary{Path: rel, Reason: "special_file"})
			return nil
		}
		if info.Size() > policy.MaxFileBytes {
			result.Skipped = append(result.Skipped, PathSummary{Path: rel, Bytes: info.Size(), Reason: "max_file_bytes"})
			return nil
		}
		state, stable, err := readStable(path, info)
		if err != nil {
			return fmt.Errorf("read config path %q: %w", rel, err)
		}
		if !stable {
			result.Skipped = append(result.Skipped, PathSummary{Path: rel, Bytes: info.Size(), Reason: "file_changing"})
			return nil
		}
		result.Files[rel] = state
		return nil
	})
	sort.Slice(result.Skipped, func(i, j int) bool { return result.Skipped[i].Path < result.Skipped[j].Path })
	return result, err
}

func mayContainManaged(rel string, policy Policy) bool {
	if rel == ".paperboat" || strings.HasPrefix(rel, ".paperboat/") {
		return false
	}
	first := strings.Split(filepath.ToSlash(rel), "/")[0]
	if strings.HasPrefix(first, ".") && !policy.Excluded(rel) {
		return true
	}
	for _, include := range policy.Includes {
		literal := strings.Split(include, "*")[0]
		if strings.HasPrefix(literal, rel+"/") || strings.HasPrefix(rel, strings.TrimSuffix(literal, "/")) {
			return true
		}
	}
	return false
}

func relativeForError(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

func readStable(path string, before fs.FileInfo) (fileState, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return fileState{}, false, err
	}
	hash := sha256.New()
	bytes, err := io.Copy(hash, file)
	closeErr := file.Close()
	if err != nil {
		return fileState{}, false, err
	}
	if closeErr != nil {
		return fileState{}, false, closeErr
	}
	after, err := os.Stat(path)
	if err != nil {
		return fileState{}, false, err
	}
	stable := before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && before.Mode() == after.Mode()
	return fileState{Hash: hex.EncodeToString(hash.Sum(nil)), Bytes: bytes, Mode: after.Mode().Perm()}, stable, nil
}

func portableSymlink(home, path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(path), resolved)
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", errors.New("symlink target cannot be resolved")
	}
	canonicalHome, err := filepath.EvalSymlinks(home)
	if err != nil || !sameOrInside(resolved, canonicalHome) {
		return "", errors.New("symlink escapes config home")
	}
	relativeToHome, err := filepath.Rel(canonicalHome, resolved)
	if err != nil {
		return "", errors.New("symlink target is not portable")
	}
	portable, err := filepath.Rel(filepath.Dir(path), filepath.Join(home, relativeToHome))
	if err != nil || filepath.IsAbs(portable) {
		return "", errors.New("symlink target is not portable")
	}
	return portable, nil
}

func copyState(sourceRoot, destinationRoot, rel string, state fileState) error {
	if err := validatePattern(rel); err != nil {
		return err
	}
	destination := filepath.Join(destinationRoot, filepath.FromSlash(rel))
	if !sameOrInside(destination, destinationRoot) {
		return errors.New("destination escaped root")
	}
	source := filepath.Join(sourceRoot, filepath.FromSlash(rel))
	return copyStatePath(source, destination, destinationRoot, rel, state)
}

func copyStatePath(source, destination, destinationRoot, displayPath string, state fileState) error {
	if !sameOrInside(destination, destinationRoot) {
		return errors.New("destination escaped root")
	}
	if err := validateDestinationParent(destinationRoot, destination); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if err := validateDestinationParent(destinationRoot, destination); err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil && info.IsDir() {
		if err := os.Remove(destination); err != nil {
			return fmt.Errorf("destination %q is a non-empty directory: %w", displayPath, err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if state.Mode&os.ModeSymlink != 0 {
		if filepath.IsAbs(state.Target) {
			return errors.New("absolute symlink target is not portable")
		}
		resolved := filepath.Clean(filepath.Join(filepath.Dir(destination), state.Target))
		if !sameOrInside(resolved, destinationRoot) {
			return errors.New("symlink target escapes destination root")
		}
		canonicalRoot, err := canonicalPath(destinationRoot)
		if err != nil {
			return err
		}
		canonicalTarget, err := canonicalPath(resolved)
		if err != nil || !sameOrInside(canonicalTarget, canonicalRoot) {
			return errors.New("symlink target escapes destination root through an existing symlink")
		}
		tmp, err := temporaryPath(filepath.Dir(destination), filepath.Base(destination))
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
		if err := os.Remove(tmp); err != nil {
			return err
		}
		if err := os.Symlink(state.Target, tmp); err != nil {
			return err
		}
		return os.Rename(tmp, destination)
	}
	before, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("source %q is not a regular file", displayPath)
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	tmp, err := temporaryPath(filepath.Dir(destination), filepath.Base(destination))
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	output, err := os.OpenFile(tmp, os.O_TRUNC|os.O_WRONLY, state.Mode.Perm())
	if err != nil {
		return err
	}
	if err := output.Chmod(state.Mode.Perm()); err != nil {
		_ = output.Close()
		return err
	}
	hash := sha256.New()
	bytes, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(copyErr, syncErr, closeErr)
	}
	after, err := os.Stat(source)
	if err != nil {
		return errors.Join(errSourceChanged, err)
	}
	copiedHash := hex.EncodeToString(hash.Sum(nil))
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() || bytes != state.Bytes || copiedHash != state.Hash || after.Mode().Perm() != state.Mode.Perm() {
		return errSourceChanged
	}
	return os.Rename(tmp, destination)
}

func validateDestinationParent(root, destination string) error {
	canonicalRoot, err := canonicalPath(root)
	if err != nil {
		return err
	}
	canonicalParent, err := canonicalPath(filepath.Dir(destination))
	if err != nil {
		return err
	}
	if !sameOrInside(canonicalParent, canonicalRoot) {
		return errors.New("destination parent escapes root through a symlink")
	}
	return nil
}

func temporaryPath(dir, base string) (string, error) {
	file, err := os.CreateTemp(dir, "."+base+".paperboat-")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
