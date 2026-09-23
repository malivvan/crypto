// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"

	ssh "github.com/malivvan/crypto/ssh/internal"
)

func ExampleNewServerConn() {
	// In the beginning, we start a listener for incoming connections.
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if c.User() == "testuser" && bytes.Equal(pass, []byte("tiger")) {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		log.Fatal(err)
	}
	hostCert := &ssh.Certificate{
		Key:         hostSigner.PublicKey(),
		CertType:    ssh.HostCert,
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := hostCert.SignCert(rand.Reader, hostSigner); err != nil {
		log.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(hostCert, hostSigner)
	if err != nil {
		log.Fatal(err)
	}
	config.AddHostKey(certSigner)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	go func() {
		nConn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		// Service the incoming Channel channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of a shell, the type is
			// "session" and ServerShell may be used to present a simple
			// terminal interface.
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Fatalf("Could not accept channel: %v", err)
			}

			// Sessions have out-of-band requests such as "shell",
			// "ptyallocate-req" and "env". Here we accept the first request
			// (the shell/exec), and discard the rest.
			req := <-requests
			if req.Type != "shell" && req.Type != "exec" {
				req.Reply(false, nil)
				channel.Close()
				continue
			}
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			channel.Write([]byte("hello world\n"))
			// Signal the exit status, then close the channel. Without an
			// exit-status message the client's Wait/Output would return an
			// error even though all data was delivered.
			channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
			channel.Close()
		}
	}()

	// Dial the server.
	conn, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("tiger")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	out, err := session.Output("")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(out))

	// Output:
	// hello world
}

func ExampleServerConfig_PublicKeyCallback() {
	// A public key may be used to authenticate against the server by
	// using an unencrypted PEM-encoded private key file.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	authorizedKey := ssh.MarshalAuthorizedKey(clientSigner.PublicKey())

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			expected, _, _, _, _ := ssh.ParseAuthorizedKey(authorizedKey)
			if bytes.Equal(expected.Marshal(), pubKey.Marshal()) {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}
	fmt.Println(config.PublicKeyCallback != nil)

	// Output:
	// true
}

func ExampleCertChecker() {
	// This example shows how to use a CertChecker to verify a user
	// certificate against a known CA.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		log.Fatal(err)
	}

	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	user, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		log.Fatal(err)
	}

	cert := &ssh.Certificate{
		Key:             user.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"user"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		log.Fatal(err)
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), ca.PublicKey().Marshal())
		},
	}
	err = checker.CheckCert("user", cert)
	fmt.Println(err == nil)

	// Output:
	// true
}
