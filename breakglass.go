// breakglass is a SSH/SCP server which unpacks received tar archives
// and allows to run commands in the unpacked archive.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/gokrazy/gokrazy"

	"golang.org/x/crypto/ssh"
)

var (
	authorizedKeysPath = flag.String("authorized_keys",
		"/perm/breakglass.authorized_keys",
		"path to an OpenSSH authorized_keys file")

	hostKeyPath = flag.String("host_key",
		"/perm/breakglass.host_key",
		"path to a PEM-encoded RSA, DSA or ECDSA private key (create using e.g. ssh-keygen -f /perm/breakglass.host_key -N '' -t rsa)")

	hostPasswordPath = flag.String("host_password",
		"/etc/gokr-pw.txt",
		"path to host password")
)

func loadAuthorizedKeys(path string) (map[string]bool, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := make(map[string]bool)

	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		if tr := strings.TrimSpace(s.Text()); tr == "" || strings.HasPrefix(tr, "#") {
			continue
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(s.Bytes())
		if err != nil {
			return nil, err
		}
		result[string(pubKey.Marshal())] = true
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func loadHostKey(path string) (ssh.Signer, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(b)
}

func createHostKey(path string) (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE, 0400)
	if err == nil {
		defer file.Close()

		err = pem.Encode(file, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	}
	if err != nil {
		log.Printf("saving generated host key failed: %v", err)
	}

	return ssh.NewSignerFromKey(key)
}

func loadPassword(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(path)
	return bytes.TrimSpace(b), err
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	config := &ssh.ServerConfig{}

	authorizedKeys, err := loadAuthorizedKeys(*authorizedKeysPath)
	if err == nil {
		// pubkey auth
		log.Printf("authorized keys found - using pubkey authorization")
		config.PublicKeyCallback = func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeys[string(pubKey.Marshal())] {
				log.Printf("user %q successfully authorized from remote addr %s", conn.User(), conn.RemoteAddr())
				return nil, nil
			}
			return nil, fmt.Errorf("public key not found in %s", *authorizedKeysPath)
		}
	} else {
		// terminal error
		if !os.IsNotExist(err) {
			log.Printf("see https://github.com/gokrazy/breakglass#installation")
			log.Fatalf("could not load authorized keys: %v", err)
		}

		hostPassword, errPass := loadPassword(*hostPasswordPath)
		if errPass != nil {
			log.Fatalf("could not load either authorized keys (%v) or host password (%v)", err, errPass)
		}

		// password auth
		log.Println("authorized keys not found - falling back to password authorization")
		config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if bytes.Compare(hostPassword, password) == 0 {
				log.Printf("user %q successfully authorized from remote addr %s", conn.User(), conn.RemoteAddr())
				return nil, nil
			}
			return nil, fmt.Errorf("public key not found in %s", *authorizedKeysPath)
		}
	}

	signer, err := loadHostKey(*hostKeyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("see https://github.com/gokrazy/breakglass#installation")
			log.Fatalf("could not load host keys: %v", err)
		}

		// create host key
		log.Println("host key not found, creating initial host key")
		signer, err = createHostKey(*hostKeyPath)
		if err != nil {
			log.Fatalf("could not create host key: %v", err)
		}
	}
	config.AddHostKey(signer)

	unpackDir, err := ioutil.TempDir("", "brokenglass")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(unpackDir)

	// This tmpfs mount ensures that our temp directory is mounted
	// without NOEXEC and that we have plenty of space for payload.
	// It will be cleaned up on process exit because each gokrazy
	// process uses a non-shared mount namespace.
	if err := syscall.Mount("tmpfs", unpackDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_RELATIME, "size=500M"); err != nil {
		log.Fatalf("tmpfs on %s: %v", unpackDir, err)
	}

	if err := os.Chdir(unpackDir); err != nil {
		log.Fatal(err)
	}

	if err := os.Setenv("PATH", unpackDir+":"+os.Getenv("PATH")); err != nil {
		log.Fatal(err)
	}

	accept := func(listener net.Listener) {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}

			go func(conn net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					log.Printf("handshake: %v", err)
					return
				}

				// discard all out of band requests
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					handleChannel(newChannel)
				}
			}(conn)
		}
	}

	addrs, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}

	for _, addr := range addrs {
		hostport := net.JoinHostPort(addr, "22")
		listener, err := net.Listen("tcp", hostport)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("listening on %s\n", hostport)
		go accept(listener)
	}

	fmt.Printf("host key fingerprint: %s\n", ssh.FingerprintSHA256(signer.PublicKey()))

	select {}
}
