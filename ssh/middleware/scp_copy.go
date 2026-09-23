package middleware

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/malivvan/crypto/ssh"
)

var (
	scpReTimestamp = regexp.MustCompile(`^T(\d{10}) 0 (\d{10}) 0$`)
	scpReNewFolder = regexp.MustCompile(`^D(\d{4}) 0 (.*)$`)
	scpReNewFile   = regexp.MustCompile(`^C(\d{4}) (\d+) (.*)$`)
)

type scpParseError struct {
	subject string
}

func (e scpParseError) Error() string {
	return fmt.Sprintf("failed to parse: %q", e.subject)
}

func scpCopyToClient(s ssh.Session, info ScpInfo, handler ScpCopyToClientHandler) error {
	matches, err := handler.Glob(s, info.Path)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return fmt.Errorf("no files matching %q", info.Path)
	}

	rootEntry := &ScpRootEntry{}
	var closers []func() error
	defer func() {
		for _, closer := range closers {
			if closer != nil {
				_ = closer()
			}
		}
	}()

	for _, match := range matches {
		if !info.Recursive {
			entry, closer, err := handler.NewFileEntry(s, match)
			closers = append(closers, closer)
			if err != nil {
				return err
			}
			rootEntry.Append(entry)
			continue
		}

		if err := handler.WalkDir(s, match, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				entry, err := handler.NewDirEntry(s, path)
				if err != nil {
					return err
				}
				rootEntry.Append(entry)
			} else {
				entry, closer, err := handler.NewFileEntry(s, path)
				if err != nil {
					return err
				}
				closers = append(closers, closer)
				rootEntry.Append(entry)
			}

			return nil
		}); err != nil {
			return err
		}
	}

	return rootEntry.Write(s)
}

func scpCopyFromClient(s ssh.Session, info ScpInfo, handler ScpCopyFromClientHandler) error {
	// accepts the request
	_, _ = s.Write(scpNull)

	var (
		path  = info.Path
		r     = bufio.NewReader(s)
		mtime int64
		atime int64
	)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to read line: %w", err)
		}
		line = strings.TrimSuffix(line, "\n")

		if matches := scpReTimestamp.FindAllStringSubmatch(line, 2); matches != nil {
			mtime, err = strconv.ParseInt(matches[0][1], 10, 64)
			if err != nil {
				return scpParseError{line}
			}
			atime, err = strconv.ParseInt(matches[0][2], 10, 64)
			if err != nil {
				return scpParseError{line}
			}

			// accepts the header
			_, _ = s.Write(scpNull)
			continue
		}

		if matches := scpReNewFile.FindAllStringSubmatch(line, 3); matches != nil {
			if len(matches) != 1 || len(matches[0]) != 4 {
				return scpParseError{line}
			}
			if err := scpHandleNewFile(s, r, handler, path, line, matches[0], mtime, atime); err != nil {
				return err
			}
			mtime = 0
			atime = 0
			continue
		}

		if matches := scpReNewFolder.FindAllStringSubmatch(line, 2); matches != nil {
			if len(matches) != 1 || len(matches[0]) != 3 {
				return scpParseError{line}
			}

			mode, err := strconv.ParseUint(matches[0][1], 8, 32)
			if err != nil {
				return scpParseError{line}
			}
			name := matches[0][2]
			if err := scpValidateName(name); err != nil {
				return err
			}

			path = filepath.Join(path, name)
			if err := handler.Mkdir(s, &ScpDirEntry{
				Name:     name,
				Filepath: path,
				Mode:     fs.FileMode(mode),
				Mtime:    mtime,
				Atime:    atime,
			}); err != nil {
				return fmt.Errorf("failed to create dir: %q: %w", name, err)
			}

			mtime = 0
			atime = 0
			// says 'hey im done'
			_, _ = s.Write(scpNull)
			continue
		}

		if line == "E" {
			path = filepath.Dir(path)

			// says 'hey im done'
			_, _ = s.Write(scpNull)
			continue
		}

		return fmt.Errorf("unhandled input: %q", line)
	}

	_, _ = s.Write(scpNull)
	return nil
}

func scpHandleNewFile(s ssh.Session, r *bufio.Reader, handler ScpCopyFromClientHandler, path, line string, match []string, mtime, atime int64) error {
	mode, err := strconv.ParseUint(match[1], 8, 32)
	if err != nil {
		return scpParseError{line}
	}

	size, err := strconv.ParseInt(match[2], 10, 64)
	if err != nil {
		return scpParseError{line}
	}
	name := match[3]
	if err := scpValidateName(name); err != nil {
		return err
	}

	// accepts the header
	_, _ = s.Write(scpNull)

	written, err := handler.Write(s, &ScpFileEntry{
		Name:     name,
		Filepath: filepath.Join(path, name),
		Mode:     fs.FileMode(mode),
		Size:     size,
		Mtime:    mtime,
		Atime:    atime,
		Reader:   newScpLimitReader(r, int(size)),
	})
	if err != nil {
		return fmt.Errorf("failed to write file: %q: %w", name, err)
	}
	if written != size {
		return fmt.Errorf("failed to write the file: %q: written %d out of %d bytes", name, written, size)
	}

	// read the trailing nil char
	_, _ = r.ReadByte()

	// says 'hey im done'
	_, _ = s.Write(scpNull)
	return nil
}

func newScpLimitReader(r io.Reader, limit int) io.Reader {
	return &scpLimitReader{
		r:    r,
		left: limit,
	}
}

type scpLimitReader struct {
	r io.Reader

	lock sync.Mutex
	left int
}

func (r *scpLimitReader) Read(b []byte) (int, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.left <= 0 {
		return 0, io.EOF
	}
	if len(b) > r.left {
		b = b[0:r.left]
	}
	n, err := r.r.Read(b)
	r.left -= n
	return n, err
}
