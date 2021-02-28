package sshd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModificationApplyWhichReplaces(t *testing.T) {
	m := modification{
		LineRegexp: regexp.MustCompile("(?m)^key.*$"),
		Key:        "key",
		Value:      "value",
	}
	assert.Equal(t, "key value\n", string(m.Apply([]byte("key old_value\n"))))
}

func TestModificationApplyWhichAppends(t *testing.T) {
	m := modification{
		LineRegexp: regexp.MustCompile("(?m)^k.+y.*$"),
		Key:        "key",
		Value:      "value",
	}
	assert.Equal(t, "ky old_value\nkey value", string(m.Apply([]byte("ky old_value\n"))))
}

func TestModifierTestConfig(t *testing.T) {
	m := Modifier{ConfigPath: "testdata/sshd_config"}
	assert.Nil(t, m.testConfig())
}

func TestModifierTestConfigFailure(t *testing.T) {
	m := Modifier{ConfigPath: "testdata/invalid"}
	assert.Error(t, m.testConfig())
}

func TestModifierTestConfigWithSSHDWarning(t *testing.T) {
	m := Modifier{ConfigPath: "testdata/unknown_hostkey"}
	assert.Error(t, m.testConfig())
}

func mustReadFixture(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := ioutil.ReadFile(path)
	assert.Nil(t, err, "could not open text fixture at %s", path)
	return contents
}

// setupModifierTest takes path to a config and a key and creates a concurrency
// safe way test Modifier on it. The returned file should be cleaned up after
// the test.
func setupModifierTest(t *testing.T) string {
	t.Helper()
	sshdConfig := mustReadFixture(t, "testdata/modifier_sshd_config")
	key := mustReadFixture(t, "testdata/ssh_host_rsa_key")
	tempDir, err := ioutil.TempDir("", "sshca-*")
	if err != nil {
		t.Skip("unable to create temporary directory for test")
	}

	// create a basic valid SSHD config
	// need to create at least one host key
	tempKeyPath := filepath.Join(tempDir, "key")
	err = ioutil.WriteFile(tempKeyPath, key, 0600)
	if err != nil {
		t.Skipf("unable to create key at %s", tempKeyPath)
	}

	// add the absolute path to the newly created key to the sshd config
	tempConfigPath := filepath.Join(tempDir, "sshd_config")
	err = ioutil.WriteFile(
		tempConfigPath,
		bytes.Join(
			[][]byte{
				sshdConfig,
				[]byte(fmt.Sprintf("HostKey %s", tempKeyPath)),
			},
			[]byte("\n"),
		),
		0644,
	)
	if err != nil {
		t.Skipf("unable to create sshd_config at %s", tempConfigPath)
	}

	return tempConfigPath
}

// cleanupModifierTest cleans up the temp dir created in setupModifierTest. The
// argument is the return value from setupModiferTest.
func cleanupModifierTest(t *testing.T, path string) {
	t.Helper()
	dirPath := filepath.Dir(path)
	if dirPath == "." || dirPath == "/" {
		t.Errorf("skip deleting unsafe dir %q", dirPath)
		t.FailNow()
	}
	err := os.RemoveAll(dirPath)
	if err != nil {
		t.Errorf("unable to delete dir %s: %s", path, err)
		t.FailNow()
	}
}

func mustLookup(t *testing.T, configPath string, key string) []string {
	t.Helper()
	results, err := Lookup(configPath, key)
	assert.Nil(t, err)
	return results
}

func TestModifierSet(t *testing.T) {
	configPath := setupModifierTest(t)
	defer cleanupModifierTest(t, configPath)
	m := Modifier{ConfigPath: configPath}
	m.Set("AcceptEnv", "EXAMPLE1")
	assert.Nil(t, m.Commit())
	assert.ElementsMatch(t,
		[]string{"EXAMPLE", "EXAMPLE1"},
		mustLookup(t, configPath, "AcceptEnv"),
	)
}

func TestModifierSetWithRestrictedRegexpChars(t *testing.T) {
	configPath := setupModifierTest(t)
	defer cleanupModifierTest(t, configPath)
	m := Modifier{ConfigPath: configPath}
	m.Set("ListenAddress", "0.0.0.1:22")
	assert.Nil(t, m.Commit())
	assert.ElementsMatch(t,
		[]string{"0.0.0.1:22", "[::]:22"},
		mustLookup(t, configPath, "ListenAddress"),
	)
}

func TestModifierSetUnique(t *testing.T) {
	configPath := setupModifierTest(t)
	defer cleanupModifierTest(t, configPath)
	m := Modifier{ConfigPath: configPath}
	m.SetUnique("Port", "23")
	assert.Nil(t, m.Commit())
	assert.ElementsMatch(t,
		[]string{"23"},
		mustLookup(t, configPath, "Port"),
	)
}

func TestModifierSetUniqueWithRestrictedRegexpChars(t *testing.T) {
	configPath := setupModifierTest(t)
	defer cleanupModifierTest(t, configPath)
	m := Modifier{ConfigPath: configPath}
	m.SetUnique("Ciphers", "+aes256-gcm@openssh.com")
	assert.Nil(t, m.Commit())
	assert.Contains(t,
		mustLookup(t, configPath, "Ciphers")[0],
		"aes256-gcm@openssh.com",
	)
}

func TestModifierCommitWithNoModification(t *testing.T) {
	m := Modifier{ConfigPath: "testdata/unwritable"}
	assert.Nil(t, m.Commit())
}

// Test a no-op modification with an unwritable file
// Modifier should not write on a no-op modification
func TestModifierWithIdentityModification(t *testing.T) {
	m := Modifier{ConfigPath: "testdata/unwritable"}
	m.Set("HostKey", "testdata/ssh_host_rsa_key")
	assert.Nil(t, m.Commit())
}

func TestModifierCommitWithInvalidFinalConfig(t *testing.T) {
	configPath := setupModifierTest(t)
	defer cleanupModifierTest(t, configPath)
	initialContents, err := ioutil.ReadFile(configPath)
	assert.Nil(t, err)
	m := Modifier{ConfigPath: configPath}
	m.Set("HostKey", "nonexistent")
	assert.Error(t, m.Commit())
	// check the file has been reverted
	finalContents, err := ioutil.ReadFile(configPath)
	assert.Nil(t, err)
	assert.Equal(t, 
		initialContents, 
		finalContents, 
		"expect the file to have been unchanged",
	)
}

// Run Set and SetUnique multiple times in one modification and verify the
// result
func TestModifierEndToEnd(t *testing.T) {
	configPath := setupModifierTest(t)
	defer cleanupModifierTest(t, configPath)
	m := Modifier{ConfigPath: configPath}
	m.SetUnique("Port", "23")
	m.Set("AcceptEnv", "EXAMPLE1")
	m.SetUnique("Port", "21")
	m.Set("AcceptEnv", "EXAMPLE2")
	assert.Nil(t, m.Commit())
	assert.ElementsMatch(t, []string{"21"}, mustLookup(t, configPath, "Port"))
	assert.ElementsMatch(t, []string{"EXAMPLE", "EXAMPLE1", "EXAMPLE2"}, mustLookup(t, configPath, "AcceptEnv"))
	m.Set("ListenAddress", "0.0.0.0:22")
	m.SetUnique("Port", "22")
	assert.Nil(t, m.Commit())
	assert.ElementsMatch(t, []string{"22"}, mustLookup(t, configPath, "Port"))
	assert.ElementsMatch(t, []string{"0.0.0.0:22", "[::]:22"}, mustLookup(t, configPath, "ListenAddress"))
}
