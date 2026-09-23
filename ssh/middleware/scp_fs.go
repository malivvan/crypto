package middleware

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malivvan/crypto/ssh"
)

// scpFileSystemHandler is a ScpHandler implementation for a given root path.
type scpFileSystemHandler struct{ root string }

var _ ScpHandler = &scpFileSystemHandler{}

// NewSCPFileSystemHandler returns an ScpHandler based on the given dir. All
// paths are resolved relative to root and access outside of it is denied.
func NewSCPFileSystemHandler(root string) ScpHandler {
	return &scpFileSystemHandler{
		root: filepath.Clean(root),
	}
}

func (h *scpFileSystemHandler) chtimes(path string, mtime, atime int64) error {
	if mtime == 0 || atime == 0 {
		return nil
	}
	p, err := h.prefixed(path)
	if err != nil {
		return err
	}
	if err := os.Chtimes(
		p,
		time.Unix(atime, 0),
		time.Unix(mtime, 0),
	); err != nil {
		return fmt.Errorf("failed to chtimes: %q: %w", path, err)
	}
	return nil
}

func (h *scpFileSystemHandler) prefixed(path string) (string, error) {
	clean := filepath.Clean(path)
	if clean == h.root || strings.HasPrefix(clean, h.root+string(filepath.Separator)) {
		return clean, nil
	}
	safe := filepath.Clean("/" + path)
	joined := filepath.Join(h.root, safe)
	if joined != h.root && !strings.HasPrefix(joined, h.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal detected: %q resolves outside root", path)
	}
	return joined, nil
}

func (h *scpFileSystemHandler) Glob(_ ssh.ServerSession, s string) ([]string, error) {
	p, err := h.prefixed(s)
	if err != nil {
		return nil, err
	}
	matches, err := filepath.Glob(p)
	if err != nil {
		return nil, err
	}

	var safe []string
	for _, match := range matches {
		if match != h.root && !strings.HasPrefix(match, h.root+string(filepath.Separator)) {
			continue
		}
		rel, err := filepath.Rel(h.root, match)
		if err != nil {
			return nil, err
		}
		safe = append(safe, rel)
	}
	return safe, nil
}

func (h *scpFileSystemHandler) WalkDir(_ ssh.ServerSession, path string, fn fs.WalkDirFunc) error {
	p, err := h.prefixed(path)
	if err != nil {
		return err
	}
	return filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		// if h.root is ./foo/bar, we don't want to serve `bar` as the root,
		// but instead its contents.
		if path == h.root {
			return err
		}
		return fn(path, d, err)
	})
}

func (h *scpFileSystemHandler) NewDirEntry(_ ssh.ServerSession, name string) (*ScpDirEntry, error) {
	path, err := h.prefixed(name)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open dir: %q: %w", path, err)
	}
	return &ScpDirEntry{
		Children: []ScpEntry{},
		Name:     info.Name(),
		Filepath: path,
		Mode:     info.Mode(),
		Mtime:    info.ModTime().Unix(),
		Atime:    info.ModTime().Unix(),
	}, nil
}

func (h *scpFileSystemHandler) NewFileEntry(_ ssh.ServerSession, name string) (*ScpFileEntry, func() error, error) {
	path, err := h.prefixed(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat %q: %w", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open %q: %w", path, err)
	}
	return &ScpFileEntry{
		Name:     info.Name(),
		Filepath: path,
		Mode:     info.Mode(),
		Size:     info.Size(),
		Mtime:    info.ModTime().Unix(),
		Atime:    info.ModTime().Unix(),
		Reader:   f,
	}, f.Close, nil
}

func (h *scpFileSystemHandler) Mkdir(_ ssh.ServerSession, entry *ScpDirEntry) error {
	p, err := h.prefixed(entry.Filepath)
	if err != nil {
		return err
	}
	if err := os.Mkdir(p, entry.Mode); err != nil {
		return fmt.Errorf("failed to create dir: %q: %w", entry.Filepath, err)
	}
	return h.chtimes(entry.Filepath, entry.Mtime, entry.Atime)
}

func (h *scpFileSystemHandler) Write(_ ssh.ServerSession, entry *ScpFileEntry) (int64, error) {
	p, err := h.prefixed(entry.Filepath)
	if err != nil {
		return 0, err
	}
	f, err := os.OpenFile(p, os.O_TRUNC|os.O_RDWR|os.O_CREATE, entry.Mode)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %q: %w", entry.Filepath, err)
	}
	defer f.Close() //nolint:errcheck
	written, err := io.Copy(f, entry.Reader)
	if err != nil {
		return 0, fmt.Errorf("failed to write file: %q: %w", entry.Filepath, err)
	}
	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("failed to close file: %q: %w", entry.Filepath, err)
	}
	return written, h.chtimes(entry.Filepath, entry.Mtime, entry.Atime)
}

// scpFSHandler is a read-only ScpCopyToClientHandler for an fs.FS.
type scpFSHandler struct{ fsys fs.FS }

var _ ScpCopyToClientHandler = &scpFSHandler{}

// NewSCPFSReadHandler returns a read-only ScpCopyToClientHandler that accepts
// any fs.FS as input.
func NewSCPFSReadHandler(fsys fs.FS) ScpCopyToClientHandler {
	return &scpFSHandler{fsys: fsys}
}

func (h *scpFSHandler) Glob(_ ssh.ServerSession, s string) ([]string, error) {
	return fs.Glob(h.fsys, s)
}

func (h *scpFSHandler) WalkDir(_ ssh.ServerSession, path string, fn fs.WalkDirFunc) error {
	return fs.WalkDir(h.fsys, path, fn)
}

func (h *scpFSHandler) NewDirEntry(_ ssh.ServerSession, path string) (*ScpDirEntry, error) {
	path = scpNormalizePath(path)
	info, err := fs.Stat(h.fsys, path)
	if err != nil {
		return nil, fmt.Errorf("failed to open dir: %q: %w", path, err)
	}
	return &ScpDirEntry{
		Children: []ScpEntry{},
		Name:     info.Name(),
		Filepath: path,
		Mode:     info.Mode(),
		Mtime:    info.ModTime().Unix(),
		Atime:    info.ModTime().Unix(),
	}, nil
}

func (h *scpFSHandler) NewFileEntry(_ ssh.ServerSession, path string) (*ScpFileEntry, func() error, error) {
	info, err := fs.Stat(h.fsys, path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat %q: %w", path, err)
	}
	f, err := h.fsys.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open %q: %w", path, err)
	}
	return &ScpFileEntry{
		Name:     info.Name(),
		Filepath: path,
		Mode:     info.Mode(),
		Size:     info.Size(),
		Mtime:    info.ModTime().Unix(),
		Atime:    info.ModTime().Unix(),
		Reader:   f,
	}, f.Close, nil
}
