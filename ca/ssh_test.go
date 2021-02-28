package ca

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const testPublicKeyString string = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHwXYROIrAfv9RS4LyCPdsPGy6EqM+vncrrZXzVJbNuV john@doe\n"

var testPublicKeyContents []byte = []byte(testPublicKeyString)

const (
	testPublicKeyFingerprint string = "SHA256:nbtA2MPjSSVod4bmKFSZ60I2DOnD0AHXXnbsL5TTPt8"
	testPublicKeyType        string = "ssh-ed25519"
)

func TestCertificateTypeString(t *testing.T) {
	assert.Equal(t, "host", HostCertificate.String())
	assert.Equal(t, "user", UserCertificate.String())
}

func TestCertificateTypeArgs(t *testing.T) {
	assert.Equal(t, []string{"-h"}, HostCertificate.Args())
	assert.Equal(t, []string{}, UserCertificate.Args())
}

func TestNewPublicKey(t *testing.T) {
	key, err := NewPublicKey("./testdata/test.pub")
	assert.Nil(t, err)
	assert.Equal(t, testPublicKeyContents, key.Data)
	assert.NotNil(t, key.key)
}

func TestNewPublicKeyNonexistent(t *testing.T) {
	_, err := NewPublicKey("./testdata/nonexistent")
	assert.Error(t, err)
}

func TestNewPublicKeyBad(t *testing.T) {
	_, err := NewPublicKey("./testdata/bad.pub")
	assert.Error(t, err)
}

func TestPublicKeyFingerprint(t *testing.T) {
	key, err := NewPublicKey("./testdata/test.pub")
	assert.Nil(t, err)
	assert.Equal(t, testPublicKeyFingerprint, key.Fingerprint())
}

func TestPublicKeyType(t *testing.T) {
	key, err := NewPublicKey("./testdata/test.pub")
	assert.Nil(t, err)
	assert.Equal(t, testPublicKeyType, key.Type())
}

func TestPublicKeyMarshal(t *testing.T) {
	key, err := NewPublicKey("./testdata/test.pub")
	assert.Nil(t, err)
	assert.Equal(t, testPublicKeyContents, key.Marshal())
}

func TestPublicKeyString(t *testing.T) {
	key, err := NewPublicKey("./testdata/test.pub")
	assert.Nil(t, err)
	assert.Equal(t, testPublicKeyString, key.String())
}
