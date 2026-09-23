package ssh_test

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/malivvan/crypto/ssh"
)

func ExampleListenAndServe() {
	ssh.ListenAndServe(":2222", func(s ssh.ServerSession) {
		io.WriteString(s, "Hello world\n")
	})
}

func ExamplePasswordAuth() {
	ssh.ListenAndServe(":2222", nil,
		ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			return pass == "secret"
		}),
	)
}

func ExampleNoPty() {
	ssh.ListenAndServe(":2222", nil, ssh.NoPty())
}

func ExamplePublicKeyAuth() {
	ssh.ListenAndServe(":2222", nil,
		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			data, _ := os.ReadFile("/path/to/allowed/key.pub")
			allowed, _, _, _, _ := ssh.ParseAuthorizedKey(data)
			return ssh.KeysEqual(key, allowed)
		}),
	)
}

func ExampleHostKeyFile() {
	ssh.ListenAndServe(":2222", nil, ssh.HostKeyFile("/path/to/host/key"))
}

// ExampleDial uses the package as a client. It starts an in-process server on
// a loopback listener and dials it, which is also a convenient way to drive a
// server from a test.
func ExampleDial() {
	srv := &ssh.Server{
		Handler: func(s ssh.ServerSession) {
			io.WriteString(s, "hello from the server\n")
			s.Exit(0)
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			return password == "secret"
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User: "alice",
		Auth: []ssh.AuthMethod{ssh.Password("secret")},
		// Pin the host key in production. The server generates a fresh
		// Ed25519 host certificate on startup, so there is nothing to pin here.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	out, err := session.Output("run the handler")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(out))

	// Output:
	// hello from the server
}
