package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestAddHostKey(t *testing.T) {
	s := Server{}
	signer, err := generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly added")
	}
	signer, err = generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly replaced")
	}
}

func TestServerShutdown(t *testing.T) {
	l := newLocalListener()
	testBytes := []byte("Hello world\n")
	s := &Server{
		Handler: func(s Session) {
			s.Write(testBytes)
			time.Sleep(50 * time.Millisecond)
		},
	}
	serveErr := make(chan error, 1)
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()
	sessDone := make(chan struct{})
	sessErr := make(chan error, 1)
	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(sessDone)
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		if err := sess.Run(""); err != nil {
			sessErr <- err
			return
		}
		if !bytes.Equal(stdout.Bytes(), testBytes) {
			sessErr <- fmt.Errorf("expected = %s; got %s", testBytes, stdout.Bytes())
			return
		}
		sessErr <- nil
	}()

	srvDone := make(chan struct{})
	shutdownErr := make(chan error, 1)
	go func() {
		defer close(srvDone)
		err := s.Shutdown(context.Background())
		shutdownErr <- err
	}()

	timeout := time.After(2 * time.Second)
	select {
	case <-timeout:
		t.Fatal("timeout")
		return
	case <-srvDone:
		if err := <-shutdownErr; err != nil {
			t.Fatal(err)
		}
		// TODO: add timeout for sessDone
		<-sessDone
		if err := <-sessErr; err != nil {
			t.Fatal(err)
		}
		if err := <-serveErr; err != nil {
			t.Fatal(err)
		}
		return
	}
}

func TestServerClose(t *testing.T) {
	l := newLocalListener()
	s := &Server{
		Handler: func(s Session) {
			time.Sleep(5 * time.Second)
		},
	}
	serveErr := make(chan error, 1)
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	clientDoneChan := make(chan struct{})
	closeDoneChan := make(chan struct{})
	clientErr := make(chan error, 1)

	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(clientDoneChan)
		<-closeDoneChan
		if err := sess.Run(""); err != nil && err != io.EOF {
			clientErr <- err
			return
		}
		clientErr <- nil
	}()

	closeErr := make(chan error, 1)
	go func() {
		err := s.Close()
		closeErr <- err
		close(closeDoneChan)
	}()

	timeout := time.After(100 * time.Millisecond)
	select {
	case <-timeout:
		t.Error("timeout")
		return
	case <-s.getDoneChan():
		<-clientDoneChan
		if err := <-clientErr; err != nil {
			t.Error(err)
		}
		if err := <-closeErr; err != nil {
			t.Error(err)
		}
		if err := <-serveErr; err != nil {
			t.Error(err)
		}
		return
	}
}

func TestServerHandshakeTimeout(t *testing.T) {
	l := newLocalListener()

	s := &Server{
		HandshakeTimeout: time.Millisecond,
	}
	go func() {
		if err := s.Serve(l); err != nil {
			t.Error(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		io.Copy(io.Discard, conn)
	}()

	select {
	case <-ch:
		return
	case <-time.After(time.Second):
		t.Fatal("client connection was not force-closed")
		return
	}
}
