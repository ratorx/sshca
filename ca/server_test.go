package ca

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var TestPublicKey = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHwXYROIrAfv9RS4LyCPdsPGy6EqM+vncrrZXzVJbNuV john@doe\n")

func TestNewServer(t *testing.T) {
	wd, err := os.Getwd()
	s, err := NewServer("./testdata/test", "./testdata/test.pub", false)
	assert.Nil(t, err, wd)
	assert.Equal(t, s.PrivateKeyPath, "./testdata/test")
	assert.Equal(t, s.PublicKey, TestPublicKey)
	assert.NotNil(t, s.sshKeygenLock)
}

func TestNewServerWithInferredPublicKey(t *testing.T) {
	s, err := NewServer("./testdata/test", "", false)
	assert.Nil(t, err)
	assert.Equal(t, s.PublicKey, TestPublicKey)
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
	assert.Equal(t, reply.CAPublicKey, TestPublicKey)
}
