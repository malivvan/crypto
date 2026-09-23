//go:build windows
// +build windows

package ssh

import (
	"os/exec"

	ssh "github.com/malivvan/crypto/ssh/internal"
	"github.com/malivvan/pty"
)

type impl struct {
	Context
	*pty.ConPTY
}

func (i *impl) IsZero() bool {
	return i.ConPTY == nil
}

func (i *impl) Name() string {
	return "windows-ptyallocate"
}

func (i *impl) Read(p []byte) (n int, err error) {
	return i.ConPTY.Read(p)
}

func (i *impl) Write(p []byte) (n int, err error) {
	return i.ConPTY.Write(p)
}

func (i *impl) Resize(w int, h int) error {
	return i.ConPTY.Resize(w, h)
}

func (i *impl) Close() error {
	return i.ConPTY.Close()
}

func (i *impl) start(c *exec.Cmd, _ ptyStartConfig) error {
	// The command runs on the pseudo-console through the command API of the
	// pty package, which starts the process inside the console and waits for it
	// the way os/exec does, so the session does not have to manage the process
	// handle itself. The session context stops the process when the session
	// ends, as exec.CommandContext would.
	run := i.ConPTY.CommandContext(i, c.Path, commandArgs(c)...)
	run.Dir, run.Env, run.SysProcAttr = c.Dir, c.Env, c.SysProcAttr
	if err := run.Start(); err != nil {
		return err
	}

	// The caller keeps the *exec.Cmd it passed in, so the process and the state
	// it ends in are reported through that one.
	c.Process = run.Process
	go func() {
		c.Err = run.Wait()
		c.ProcessState = run.ProcessState
	}()

	return nil
}

// commandArgs returns the arguments of c without the program name: the command
// API of the pty package takes the program and its arguments separately, and
// uses the path it is given as the name the process sees as argv[0].
func commandArgs(c *exec.Cmd) []string {
	if len(c.Args) < 2 {
		return nil
	}
	return c.Args[1:]
}

func newPty(ctx Context, _ string, win Window, _ ssh.TerminalModes) (impl, error) {
	c, err := pty.NewConPTY(win.Width, win.Height, 0)
	if err != nil {
		return impl{}, err
	}

	return impl{ctx, c}, nil
}
