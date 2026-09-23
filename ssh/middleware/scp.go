package middleware

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/malivvan/crypto/ssh"
)

// scpNull is a single NULL byte, used as an SCP protocol acknowledgement.
var scpNull = []byte{'\x00'}

// ScpEntry defines something that knows how to write itself and its path,
// in SCP protocol format.
type ScpEntry interface {
	// Write the current entry in SCP format.
	Write(io.Writer) error

	path() string
}

// ScpAppendableEntry defines a special kind of ScpEntry, which can contain
// children.
type ScpAppendableEntry interface {
	// Write the current entry in SCP format.
	Write(io.Writer) error

	// Append another entry to the current entry.
	Append(entry ScpEntry)
}

// ScpFileEntry is an ScpEntry that reads from a Reader, defining a file and
// its contents.
type ScpFileEntry struct {
	Name     string
	Filepath string
	Mode     fs.FileMode
	Size     int64
	Reader   io.Reader
	Atime    int64
	Mtime    int64
}

func (e *ScpFileEntry) path() string { return e.Filepath }

// Write a file to the given writer.
func (e *ScpFileEntry) Write(w io.Writer) error {
	if e.Mtime > 0 && e.Atime > 0 {
		if _, err := fmt.Fprintf(w, "T%d 0 %d 0\n", e.Mtime, e.Atime); err != nil {
			return fmt.Errorf("failed to write file: %q: %w", e.Filepath, err)
		}
	}
	if _, err := fmt.Fprintf(w, "C%s %d %s\n", scpOctalPerms(e.Mode), e.Size, e.Name); err != nil {
		return fmt.Errorf("failed to write file: %q: %w", e.Filepath, err)
	}

	if _, err := io.Copy(w, e.Reader); err != nil {
		return fmt.Errorf("failed to read file: %q: %w", e.Filepath, err)
	}

	if _, err := w.Write(scpNull); err != nil {
		return fmt.Errorf("failed to write file: %q: %w", e.Filepath, err)
	}
	return nil
}

// ScpRootEntry is a root entry that can only have children.
type ScpRootEntry []ScpEntry

// Append the given entry to a child directory, or the root entry itself if
// none matches.
func (e *ScpRootEntry) Append(entry ScpEntry) {
	parent := scpNormalizePath(filepath.Dir(entry.path()))

	for _, child := range *e {
		switch dir := child.(type) {
		case *ScpDirEntry:
			if child.path() == parent {
				dir.Children = append(dir.Children, entry)
				return
			}
			if strings.HasPrefix(parent, scpNormalizePath(dir.Filepath)) {
				dir.Append(entry)
				return
			}
		default:
			continue
		}
	}

	*e = append(*e, entry)
}

// Write recursively writes all the children to the given writer.
func (e *ScpRootEntry) Write(w io.Writer) error {
	for _, child := range *e {
		if err := child.Write(w); err != nil {
			return err
		}
	}
	return nil
}

// ScpDirEntry is an ScpEntry with mode, possibly children, and possibly a
// parent.
type ScpDirEntry struct {
	Children []ScpEntry
	Name     string
	Filepath string
	Mode     fs.FileMode
	Atime    int64
	Mtime    int64
}

func (e *ScpDirEntry) path() string { return e.Filepath }

// Write the current dir entry, all its contents (recursively), and the
// dir closing to the given writer.
func (e *ScpDirEntry) Write(w io.Writer) error {
	if e.Mtime > 0 && e.Atime > 0 {
		if _, err := fmt.Fprintf(w, "T%d 0 %d 0\n", e.Mtime, e.Atime); err != nil {
			return fmt.Errorf("failed to write dir: %q: %w", e.Filepath, err)
		}
	}
	if _, err := fmt.Fprintf(w, "D%s 0 %s\n", scpOctalPerms(e.Mode), e.Name); err != nil {
		return fmt.Errorf("failed to write dir: %q: %w", e.Filepath, err)
	}

	for _, child := range e.Children {
		if err := child.Write(w); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprint(w, "E\n"); err != nil {
		return fmt.Errorf("failed to write dir: %q: %w", e.Filepath, err)
	}
	return nil
}

// Append adds an entry to the folder or their children.
func (e *ScpDirEntry) Append(entry ScpEntry) {
	parent := scpNormalizePath(filepath.Dir(entry.path()))

	for _, child := range e.Children {
		switch dir := child.(type) {
		case *ScpDirEntry:
			if child.path() == parent {
				dir.Children = append(dir.Children, entry)
				return
			}
			if strings.HasPrefix(parent, scpNormalizePath(dir.path())) {
				dir.Append(entry)
				return
			}
		default:
			continue
		}
	}

	e.Children = append(e.Children, entry)
}

// ScpOp defines which kind of SCP operation is going on.
type ScpOp byte

const (
	// ScpCopyToClient is when a file is being copied from the server to the client.
	ScpCopyToClient ScpOp = 'f'

	// ScpCopyFromClient is when a file is being copied from the client into the server.
	ScpCopyFromClient ScpOp = 't'
)

// ScpInfo provides some information about the current SCP operation.
type ScpInfo struct {
	// Ok is true if the current session is an SCP session.
	Ok bool

	// Recursive is true if it's a recursive SCP operation.
	Recursive bool

	// Path is the server path of the SCP operation.
	Path string

	// Op is the SCP operation kind.
	Op ScpOp
}

// ScpGetInfo returns information about the given command, determining
// whether it is an SCP invocation.
func ScpGetInfo(cmd []string) ScpInfo {
	info := ScpInfo{}
	if len(cmd) == 0 || cmd[0] != "scp" {
		return info
	}

	for i, p := range cmd {
		switch p {
		case "-r":
			info.Recursive = true
		case "-f":
			if i+1 >= len(cmd) {
				return info
			}
			info.Op = ScpCopyToClient
			info.Path = cmd[i+1]
		case "-t":
			if i+1 >= len(cmd) {
				return info
			}
			info.Op = ScpCopyFromClient
			info.Path = cmd[i+1]
		}
	}

	info.Ok = true
	return info
}

// ScpCopyToClientHandler is implemented to handle files being copied from
// the server to the client.
type ScpCopyToClientHandler interface {
	// Glob should be implemented if you want to provide server-side globbing
	// support.
	//
	// A minimal implementation to disable it is to return `[]string{s}, nil`.
	//
	// Note: if your other functions expect a relative path, make sure that
	// your Glob implementation returns relative paths as well.
	Glob(ssh.Session, string) ([]string, error)

	// WalkDir must be implemented if you want to allow recursive copies.
	WalkDir(ssh.Session, string, fs.WalkDirFunc) error

	// NewDirEntry should provide a *ScpDirEntry for the given path.
	NewDirEntry(ssh.Session, string) (*ScpDirEntry, error)

	// NewFileEntry should provide a *ScpFileEntry for the given path.
	// Users may also provide a closing function.
	NewFileEntry(ssh.Session, string) (*ScpFileEntry, func() error, error)
}

// ScpCopyFromClientHandler is implemented to handle files being copied from
// the client to the server.
type ScpCopyFromClientHandler interface {
	// Mkdir should create the given dir.
	// Note that this usually shouldn't use os.MkdirAll and the like.
	Mkdir(ssh.Session, *ScpDirEntry) error

	// Write should write the given file.
	Write(ssh.Session, *ScpFileEntry) (int64, error)
}

// ScpHandler is implemented to handle both SCP directions.
type ScpHandler interface {
	ScpCopyFromClientHandler
	ScpCopyToClientHandler
}

// SCP provides a middleware using the given ScpCopyToClientHandler and
// ScpCopyFromClientHandler to serve SCP (`scp -f`/`scp -t`) requests, and
// passes through to the next handler for any other command.
func SCP(rh ScpCopyToClientHandler, wh ScpCopyFromClientHandler) ssh.Middleware {
	return func(sh ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			info := ScpGetInfo(s.Command())
			if !info.Ok {
				sh(s)
				return
			}

			var err error
			switch info.Op {
			case ScpCopyToClient:
				if rh == nil {
					err = fmt.Errorf("no handler provided for scp -f")
					break
				}
				err = scpCopyToClient(s, info, rh)
			case ScpCopyFromClient:
				if wh == nil {
					err = fmt.Errorf("no handler provided for scp -t")
					break
				}
				err = scpCopyFromClient(s, info, wh)
			}
			if err != nil {
				_, _ = fmt.Fprintln(s.Stderr(), err)
				_ = s.Exit(1)
				return
			}
		}
	}
}

func scpOctalPerms(info fs.FileMode) string {
	return "0" + strconv.FormatUint(uint64(info.Perm()), 8)
}

func scpNormalizePath(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		return strings.ReplaceAll(p, "\\", "/")
	}
	return p
}

func scpValidateName(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("invalid filename: %q", name)
	}
	return nil
}
