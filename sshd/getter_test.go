package sshd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const sshdConfigPath = "testdata/sshd_config"
const invalidSSHDConfigPath = "testdata/invalid"
var expectedHostKeys = []string{
		MustFilepath("testdata/ssh_host_rsa_key"),
		MustFilepath("testdata/ssh_host_ed25519_key"),
}

func MustFilepath(path string) string {
	ret, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return ret
}

func TestLookupFromDefaultConfig(t *testing.T) {
	vals, err := Lookup(sshdConfigPath, "port")
	assert.Nil(t, err)
	assert.Equal(t, []string{"22"}, vals)
}

func TestLookupFromExplicitConfig(t *testing.T) {
	vals, err := Lookup(sshdConfigPath, "usepam")
	assert.Nil(t, err)
	assert.Equal(t, []string{"yes"}, vals)
}

func TestLookupWithCapitalizedKey(t *testing.T) {
	vals, err := Lookup(sshdConfigPath, "UsePAM")
	assert.Nil(t, err)
	assert.Equal(t, []string{"yes"}, vals)
}

func TestLookupWithMultipleValues(t *testing.T) {
	vals, err := Lookup(sshdConfigPath, "hostkey")
	assert.Nil(t, err)
	assert.ElementsMatch(t, expectedHostKeys, vals)
}

func TestLookupNonExistentConfig(t *testing.T) {
	_, err := Lookup("testdata/nonexistent", "hostkey")
	assert.Error(t, err)
}

func TestLookupInvalidConfig(t *testing.T) {
	_, err := Lookup(invalidSSHDConfigPath, "hostkey")
	assert.Error(t, err)
}
