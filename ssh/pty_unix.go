//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package ssh

import (
	"os"
	"os/exec"
	"syscall"

	ssh "github.com/malivvan/crypto/ssh/internal"
	"github.com/malivvan/pty"
)

type impl struct {
	// Master is the master PTY file descriptor.
	Master *os.File

	// Slave is the slave PTY file descriptor.
	Slave *os.File
}

func (i *impl) IsZero() bool {
	return i.Master == nil && i.Slave == nil
}

// Name returns the name of the slave PTY.
func (i *impl) Name() string {
	return i.Slave.Name()
}

// Read implements ptyInterface.
func (i *impl) Read(p []byte) (n int, err error) {
	return i.Master.Read(p)
}

// Write implements ptyInterface.
func (i *impl) Write(p []byte) (n int, err error) {
	return i.Master.Write(p)
}

func (i *impl) Close() error {
	if err := i.Master.Close(); err != nil {
		return err
	}
	return i.Slave.Close()
}

func (i *impl) Resize(w int, h int) error {
	return pty.SetSize(i.Master, &pty.Winsize{
		Rows: uint16(h), //nolint:gosec // PTY dimensions are small, positive values
		Cols: uint16(w), //nolint:gosec // PTY dimensions are small, positive values
	})
}

func (i *impl) start(c *exec.Cmd, cfg ptyStartConfig) error {
	c.Stdin, c.Stdout, c.Stderr = i.Slave, i.Slave, i.Slave
	if cfg.jobControl {
		if c.SysProcAttr == nil {
			c.SysProcAttr = &syscall.SysProcAttr{}
		}
		c.SysProcAttr.Setsid = true
		c.SysProcAttr.Setctty = true
	}
	return c.Start()
}

func newPty(_ Context, _ string, win Window, modes ssh.TerminalModes) (impl, error) {
	ptm, pts, err := pty.Open()
	if err != nil {
		return impl{}, err
	}

	// The terminal modes and the window size of the request are applied through
	// the master end: the two ends of a pseudo-terminal share one set of
	// terminal settings.
	if err := pty.ApplyTerminalModes(int(ptm.Fd()), win.Width, win.Height, modes); err != nil {
		// A pair that cannot be configured is closed rather than leaked.
		_ = ptm.Close() // Best effort.
		_ = pts.Close() // Best effort.
		return impl{}, err
	}

	return impl{Master: ptm, Slave: pts}, nil
}
