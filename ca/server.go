package ca

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
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

	publicKey, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return Server{}, fmt.Errorf("failed to read public key at %s: %w", publicKeyPath, err)
	}

	return Server{privateKeyPath, publicKey, skipConfirmation, &sync.Mutex{}}, nil
}

// CertificateType represents the type of the certificate in the request
type CertificateType bool
const (
	// HostCertificate represents a SSH host certficate
	HostCertificate CertificateType = true
	// UserCertificate represents a SSH user certificate
	UserCertificate CertificateType = false
)

// String implementation for Stringer
func (ct CertificateType) String() string {
	switch ct {
	case HostCertificate:
		return "host"
	default:
		return "user"
	}
}

func (ct CertificateType) sshKeygenArgs() []string {
	switch ct {
	case HostCertificate:
		return []string{"-h"}
	default:
		return []string{}
	}
}

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
	PublicKey []byte
}

// Identify identifies a SignPublicKey request. It generates a string version of
// the request parameters and the key fingerprint. As a side-effect, this also
// validates the public key.
func (args *SignArgs) Identify() (string, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(args.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}
	return fmt.Sprintf(
		"make %s certficate for %s key (fingerprint %s) for %s",
		args.CertificateType,
		publicKey.Type(),
		ssh.FingerprintSHA256(publicKey),
		strings.Join(args.Principals, ","),
	), nil
}

// SignReply represents the reply from SignPublicKey
type SignReply struct {
	// Certificate contains the signed SSH certificate.
	Certificate []byte
}

// SignPublicKey takes a SSH public key and signing options and signs it with
// ssh-keygen
func (ca *Server) SignPublicKey(args SignArgs, reply *SignReply) error {
	// Verify the signing request
	id, err := args.Identify()
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	fmt.Println(id)
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

// getSSHKeygenArgs builds the command line for sshKeygen by converting the
// various arguments to their corresponding ssh-keygen flags.
func (ca *Server) getSSHKeygenArgs(args SignArgs, keyPath string) []string {
	cmdArgs := []string{
		"-I", args.Identity,
		"-s", ca.PrivateKeyPath,
		"-n", strings.Join(args.Principals, ","),
	}

	cmdArgs = append(cmdArgs, args.CertificateType.sshKeygenArgs()...)
	cmdArgs = append(cmdArgs, keyPath)

	return cmdArgs
}

// runSSHKeygen runs ssh-keygen after giving it access to the server's standard
// IO, because it might be required for authentication.
func (ca *Server) runSSHKeygen(args []string) error {
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Lock the mutex to prevent confusion when signing multiple requests
	ca.sshKeygenLock.Lock()
	defer ca.sshKeygenLock.Unlock()
	if err := cmd.Run(); err != nil {
		// Unwrapping the error is possibly dangerous (might expect to keep using
		// stderr after mutex is unlocked). Explicitly convert to string before
		// returning. May not be strictly necessary, but I CBA to test and find out.
		return fmt.Errorf("failed to sign key (see server for extra details): %s", err.Error())
	}
	return nil
}

// confirmRequest waits for user confirmation for certificate signing. Any input
// followed by a newline is considered confirmation. Perhaps the error message
// for the client could be made nicer if it looked at the input. Currently, the
// client gets an EOF because the Ctrl-C shuts down the server.
func (ca *Server) confirmRequest() error {
	if ca.SkipConfirmation {
		return nil
	}
	reader := bufio.NewReader(os.Stdin)
	_, err := reader.ReadString('\n')
	return err
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
