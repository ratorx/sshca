package ca

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Server encapsulates a SSH CA and provides a net/rpc compatible type
// signature. It exposes functions to sign public keys and return the public CA
// certificate.
type Server struct {
	// PrivateKeyPath is the path to the private key for the CA.
	// This is never read by the program, but rather used as an argument for
	// ssh-keygen.
	PrivateKeyPath string
	// PublicKey is the public key of the CA.
	// This is read into the server on startup in order to respond to
	// GetCAPublicKey.
	PublicKey []byte
	// Signing passes through standard IO to ssh-keygen (for password etc.)
	// This mutex protects the critical section
	sshKeygenLock  *sync.Mutex
}

// NewServer constructs a CAServer using the paths to a SSH CA private key and
// public key. If publicKeyPath is the empty string, it is inferred from the
// privateKeyPath.
func NewServer(privateKeyPath string, publicKeyPath string) (Server, error) {
	// Perform some basic checks on the private key.
	// Provide nice errors for things that will cause ssh-keygen to fail later.
	// Nothing should rely on this for security (because that would be TOCTOU)
	privateKeyInfo, err := os.Stat(privateKeyPath)
	if err != nil {
		return Server{}, fmt.Errorf("failed to stat the private key at %s: %w", privateKeyPath, err)
	} else if privateKeyInfo.IsDir() {
		return Server{}, fmt.Errorf("private key path %s points to a directory", privateKeyPath)
	}
	
	if publicKeyPath == "" {
		publicKeyPath = privateKeyPath + ".pub"
	}

	publicKey, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return Server{}, fmt.Errorf("failed to read public key at %s: %w", publicKeyPath, err)
	}

	return Server{privateKeyPath, publicKey, &sync.Mutex{}}, nil
}

// SignArgs represents the options available (or at least an important
// subset of them) when generating the command line.
type SignArgs struct {
	// Identity is passed as the argument to -I in ssh-keygen.
	Identity string
	// IsHostKey is true when -h is passed to ssh-keygen.
	IsHostKey bool
	// Principals is passed as the argument to -n to ssh-keygen.
	Principals []string
	// PublicKey contains the regular SSH public key that is being signed.
	PublicKey []byte
}

// SignReply represents the reply from SignPublicKey
type SignReply struct {
	// Certificate contains the signed SSH certificate.
	Certificate []byte
}

// SignPublicKey takes a SSH public key and signing options and signs it with
// ssh-keygen
func (ca *Server) SignPublicKey(args SignArgs, reply *SignReply) error {
	// Prepare key for ssh-keygen, which reads files on disk
	// It's probably possible to pass in the key to stdin, but that makes passing
	// user input to ssh-keygen more complex.
	tempDir, err := ioutil.TempDir("", "sshca.")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "key.pub")
	err = ioutil.WriteFile(keyPath, ca.PublicKey, 0600)
	if err != nil {
		return fmt.Errorf("failed write key to disk: %w", err)
	}

	sshKeygenArgs := ca.getSSHKeygenArgs(args, keyPath)
	err = ca.runSSHKeygen(sshKeygenArgs)
	if err != nil {
		return err
	}

	certificate, err := ioutil.ReadFile(filepath.Join(tempDir, "key-cert.pub"))
	if err != nil {
		return fmt.Errorf("failed to read certificate from disk: %w", err)
	}

	reply.Certificate = certificate
	return nil
}

func (ca *Server) getSSHKeygenArgs(args SignArgs, keyPath string) []string {
	cmdArgs := []string{
		"-I", args.Identity,
		"-s", ca.PrivateKeyPath,
		"-n", strings.Join(args.Principals, ","),
	}

	if args.IsHostKey {
		cmdArgs = append(cmdArgs, "-h")
	}

	cmdArgs = append(cmdArgs, keyPath)


	return cmdArgs
}

func (ca *Server) runSSHKeygen(args []string) error {
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Lock the mutex to prevent confusion when signing multiple requests
	ca.sshKeygenLock.Lock()
	defer ca.sshKeygenLock.Unlock()
	fmt.Printf("Run: %s\n", cmd.String())
	err := cmd.Run()
	if err != nil {
		// Unwrapping the error is possibly dangerous (might expect to keep using
		// stderr after mutex is unlocked). Explicitly convert to string before
		// returning. May not be strictly necessary, but I CBA to test and find out.
		return fmt.Errorf("failed to sign key (see server for extra details): %s", err.Error())
	}
	return nil
}

// PublicKeyReply encapsulates the public key of the CA and represents the
// value of GetCAPublicKey.
type PublicKeyReply struct {
	CAPublicKey []byte
}

// GetCAPublicKey returns the public key of the trusted CA
func (ca *Server) GetCAPublicKey(args struct{}, reply *PublicKeyReply) error {
	reply.CAPublicKey = ca.PublicKey
	return nil
}
