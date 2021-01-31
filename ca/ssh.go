package ca

import (
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

// CertificateType represents the type of the certificate in the request
type CertificateType bool

const (
	// HostCertificate represents a SSH host certficate
	HostCertificate CertificateType = true
	// UserCertificate represents a SSH user certificate
	UserCertificate CertificateType = false
)

// String implementation for Stringer.
func (ct CertificateType) String() string {
	switch ct {
	case HostCertificate:
		return "host"
	default:
		return "user"
	}
}

// Args converts the CertificateType into ssh-keygen args.
func (ct CertificateType) Args() []string {
	switch ct {
	case HostCertificate:
		return []string{"-h"}
	default:
		return []string{}
	}
}

// PublicKey is a wrapper around an ssh.PublicKey which uses the file
// representation, rather than the wire representation.
type PublicKey struct {
	key  ssh.PublicKey
	Data []byte
}

// NewPublicKey creates a new PublicKey from a file.
func NewPublicKey(filename string) (*PublicKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key at %s: %w", filename, err)
	}
	publicKey := &PublicKey{nil, data}
	return publicKey, publicKey.parse()
}

// WriteFile writes the PublicKey to a file.
func (p *PublicKey) WriteFile(filename string, perm os.FileMode) error {
	return ioutil.WriteFile(filename, p.Data, perm)
}

// Fingerprint returns the SHA256 fingerprint of the public key.
func (p *PublicKey) Fingerprint() string {
	p.mustParse()
	return ssh.FingerprintSHA256(p.key)
}

// Type returns the algorithm of the public key.
func (p *PublicKey) Type() string {
	p.mustParse()
	return p.key.Type()
}

// Marshal returns the underlying bytes of the public key.
func (p *PublicKey) Marshal() []byte {
	ret := make([]byte, len(p.Data))
	copy(ret, p.Data)
	return ret
}

func (p *PublicKey) String() string {
	return string(p.Data)
}

// RPC Hacks. gob can't transparently support ssh.PublicKey. Instead, we ignore
// it when transmitting and initialize it transparently when the parsed version
// of the public key is needed.

// parse takes a semi-initialized PublicKey and fully initializes it. Error is
// returned if parsing fails.
func (p *PublicKey) parse() error {
	if p.key != nil {
		return nil
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(p.Data)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	p.key = pubKey
	return nil
}

// mustParse is a wrapper around parse that panics.
func (p *PublicKey) mustParse() {
	err := p.parse()
	if err != nil {
		panic(fmt.Errorf("invalid uninitialized public key: %w", err))
	}
}
