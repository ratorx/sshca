package ca

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SignArgs represents the options available (or at least an important
// subset of them) when generating the command line.
type SignArgs struct {
	// Identity is passed as the argument to -I in ssh-keygen.
	Identity string
	// CertificateType represents the type of certificate to be generated. If it's a host
	// certificate, then -h is passed to ssh-keygen.
	CertificateType CertificateType
	// Principals is passed as the argument to -n to ssh-keygen.
	Principals []string
	// PublicKey contains the regular SSH public key that is being signed.
	PublicKey *PublicKey
}

// String identifies a SignPublicKey request. It generates a string version of
// the request parameters and the key fingerprint. As a side-effect, this also
// validates the public key.
func (args SignArgs) String() string {
	return fmt.Sprintf(
		"make %s certficate for %s key (fingerprint %s) for %s",
		args.CertificateType,
		args.PublicKey.Type(),
		args.PublicKey.Fingerprint(),
		strings.Join(args.Principals, ","),
	)
}

// Args converts SignArgs to ssh-keygen args
func (args SignArgs) Args() []string {
	cmdArgs := []string{
		"-I", args.Identity,
		"-n", strings.Join(args.Principals, ","),
	}
	return append(cmdArgs, args.CertificateType.Args()...)
}

// SignReply represents the reply from SignPublicKey
type SignReply struct {
	// Certificate contains the signed SSH certificate.
	Certificate *PublicKey
}

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
	PublicKey *PublicKey
	// True iff confirmation should be skipped when responding to SignPublicKey.
	SkipConfirmation bool
	// Signing passes through standard IO to ssh-keygen (for password etc.)
	// This mutex protects the critical section
	sshKeygenLock *sync.Mutex
}

// NewServer constructs a CAServer using the paths to a SSH CA private key and
// public key. If publicKeyPath is the empty string, it is inferred from the
// privateKeyPath.
func NewServer(privateKeyPath string, publicKeyPath string, skipConfirmation bool) (Server, error) {
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

	publicKey, err := NewPublicKey(publicKeyPath)
	if err != nil {
		return Server{}, fmt.Errorf("failed to read public key at %s: %w", publicKeyPath, err)
	}

	return Server{privateKeyPath, publicKey, skipConfirmation, &sync.Mutex{}}, nil
}

// SignPublicKey takes a SSH public key and signing options and signs it with
// ssh-keygen
func (ca *Server) SignPublicKey(args SignArgs, reply *SignReply) error {
	// Lock the mutex to prevent confusion when signing multiple requests
	ca.sshKeygenLock.Lock()
	defer ca.sshKeygenLock.Unlock()

	// Verify the signing request
	fmt.Println(args)
	if err := ca.confirmRequest(); err != nil {
		return fmt.Errorf("failed to confirm request: %w", err)
	}

	// Prepare key for ssh-keygen, which reads files on disk
	// It's probably possible to pass in the key to stdin, but that makes passing
	// user input to ssh-keygen more complex.
	tempDir, err := ioutil.TempDir("", "sshca.")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "key.pub")
	err = args.PublicKey.WriteFile(keyPath, 0o600)
	if err != nil {
		return fmt.Errorf("failed write key to disk: %w", err)
	}
	sshKeygenArgs := ca.getSSHKeygenArgs(args, keyPath)
	err = runSSHKeygen(sshKeygenArgs)
	if err != nil {
		return err
	}
	// Add a newline before next prompt
	fmt.Println()

	certificate, err := NewPublicKey(filepath.Join(tempDir, "key-cert.pub"))
	if err != nil {
		return fmt.Errorf("failed to read certificate from disk: %w", err)
	}

	reply.Certificate = certificate
	return nil
}

// getSSHKeygenArgs builds the command line for sshKeygen by converting the
// various arguments to their corresponding ssh-keygen flags.
func (ca Server) getSSHKeygenArgs(args SignArgs, keyPath string) []string {
	argsSlice := args.Args()
	return append(argsSlice, "-s", ca.PrivateKeyPath, keyPath)
}

// confirmRequest waits for user confirmation for certificate signing. Any input
// followed by a newline is considered confirmation. Perhaps the error message
// for the client could be made nicer if it looked at the input. Currently, the
// client gets an EOF because the Ctrl-C shuts down the server.
func (ca Server) confirmRequest() error {
	if ca.SkipConfirmation {
		return nil
	}
	fmt.Print("press Enter to confirm (or Ctrl-C to exit)")
	reader := bufio.NewReader(os.Stdin)
	_, err := reader.ReadString('\n')
	return err
}

// PublicKeyReply encapsulates the public key of the CA and represents the
// value of GetCAPublicKey.
type PublicKeyReply struct {
	CAPublicKey *PublicKey
}

// GetCAPublicKey returns the public key of the trusted CA
func (ca Server) GetCAPublicKey(args struct{}, reply *PublicKeyReply) error {
	fmt.Print("get CA public key\n\n")
	reply.CAPublicKey = ca.PublicKey
	return nil
}
