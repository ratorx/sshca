package ca

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testPublicKey *PublicKey
var testCertDetails []byte = []byte(
`(stdin):1:
        Type: ssh-ed25519-cert-v01@openssh.com host certificate
        Public key: ED25519-CERT SHA256:nbtA2MPjSSVod4bmKFSZ60I2DOnD0AHXXnbsL5TTPt8
        Signing CA: RSA SHA256:h9xSScM9JGIUIa0BFF9XlcLCplH8mg1+DnMWh7AANjA (using rsa-sha2-512)
        Key ID: "asdf"
        Serial: 0
        Valid: forever
        Principals: 
                asdf
        Critical Options: (none)
        Extensions: (none)
`,
)

func init() {
	var err error
	testPublicKey, err = NewPublicKey("./testdata/test.pub")
	if err != nil {
		panic(fmt.Errorf("couldn't find test public key: %w", err))
	}
}

func TestSignArgsStringWithOnePrincipal(t *testing.T) {
	sa := SignArgs{
		Identity:        "",
		CertificateType: HostCertificate,
		Principals:      []string{"asdf"},
		PublicKey:       testPublicKey,
	}
	assert.Equal(t, "make host certficate for ssh-ed25519 key (fingerprint SHA256:nbtA2MPjSSVod4bmKFSZ60I2DOnD0AHXXnbsL5TTPt8) for asdf", sa.String())
}

func TestSignArgsStringWithMultiplePrincipals(t *testing.T) {
	sa := SignArgs{
		Identity:        "",
		CertificateType: UserCertificate,
		Principals:      []string{"asdf", "qwerty"},
		PublicKey:       testPublicKey,
	}
	assert.Equal(t, "make user certficate for ssh-ed25519 key (fingerprint SHA256:nbtA2MPjSSVod4bmKFSZ60I2DOnD0AHXXnbsL5TTPt8) for asdf,qwerty", sa.String())
}

func TestSignArgsToArgs(t *testing.T) {
	sa := SignArgs{
		Identity:        "example",
		CertificateType: HostCertificate,
		Principals:      []string{"asdf", "qwerty"},
		PublicKey:       testPublicKey,
	}

	assert.Equal(t, []string{"-I", "example", "-n", "asdf,qwerty", "-h"}, sa.Args())
}

func TestNewServer(t *testing.T) {
	s, err := NewServer("./testdata/test", "./testdata/test.pub", false)
	assert.Nil(t, err)
	assert.Equal(t, "./testdata/test", s.PrivateKeyPath)
	assert.Equal(t, testPublicKey, s.PublicKey)
	assert.NotNil(t, s.sshKeygenLock)
}

func TestNewServerWithInferredPublicKey(t *testing.T) {
	s, err := NewServer("./testdata/test", "", false)
	assert.Nil(t, err)
	assert.Equal(t, testPublicKey, s.PublicKey)
}

func TestNewServerWithMissingPrivateKey(t *testing.T) {
	_, err := NewServer("./testdata/nonexistent", "", false)
	assert.Error(t, err)
}

func TestNewServerWithDirectoryAsPrivateKey(t *testing.T) {
	_, err := NewServer("./testdata/fake", "", false)
	assert.Error(t, err)
}

func TestNewServerWithNoPublicKey(t *testing.T) {
	_, err := NewServer("./testdata/test2", "", false)
	assert.Error(t, err)
}

func TestServerGetCAPublicKey(t *testing.T) {
	s, err := NewServer("./testdata/test", "", false)
	assert.Nil(t, err)

	var reply PublicKeyReply
	err = s.GetCAPublicKey(struct{}{}, &reply)
	assert.Nil(t, err)
	assert.Equal(t, testPublicKey, reply.CAPublicKey)
}

func TestServerGetSSHKeygenArgs(t *testing.T) {
	server, err := NewServer("./testdata/test", "", false)
	assert.Nil(t, err)
	args := SignArgs{"", UserCertificate, []string{""}, testPublicKey}
	assert.Equal(t, append(args.Args(), "-s", "./testdata/test", "asdf"), server.getSSHKeygenArgs(args, "asdf"))
}

func getCertificateDetails(cert *PublicKey) ([]byte, error) {
	cmd := exec.Command("ssh-keygen", "-L", "-f", "-")
	buffer := bytes.Buffer{}
	buffer.Write(cert.Data)
	cmd.Stdin = &buffer
	return cmd.Output()
}

func TestServerSignPublicKey(t *testing.T) {
	_, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skipf("CLI dependency not found: %s", err)
	}
	t.Fail()
	server, err := NewServer("./testdata/ca", "", true)
	assert.Nil(t, err)
	var reply SignReply
	err = server.SignPublicKey(SignArgs{"asdf", HostCertificate, []string{"asdf"}, testPublicKey}, &reply)
	assert.Nil(t, err)
	details, err := getCertificateDetails(reply.Certificate)
	assert.Nil(t, err)
	assert.Equal(t, testCertDetails, details)
}
