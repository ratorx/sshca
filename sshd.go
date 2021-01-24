package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"regexp"
	"strings"
)

// SSHDConfig provides a safe wrapper to modify SSHD configuration. Changes are
// verified before being commited. If verification fails, the original file is
// restored.
type SSHDConfig struct {
	ConfigPath    string
	modifications []func([]byte) []byte
}

func (s *SSHDConfig) testConfig() error {
	cmd := exec.Command("sshd", "-t")
	return runCommand(cmd)
}

// Set is a function to set SSHD config options. Calling this function does not
// verify the validity of the configuration or make any changes to the SSHD
// config file. This is the responsibility of Commit.
func (s *SSHDConfig) Set(key, value string, uniqueKey bool) {
	var keyRegexp *regexp.Regexp
	// Use MustCompile because a failure here indicates a programming error rather
	// than input error
	if uniqueKey {
		keyRegexp = regexp.MustCompile(fmt.Sprintf("(?m)^#?%s.*$", regexp.QuoteMeta(key)))
	} else {
		keyRegexp = regexp.MustCompile(fmt.Sprintf("(?m)^#?%s %s.*$", regexp.QuoteMeta(key), regexp.QuoteMeta(value)))
	}

	modifyFunc := func(b []byte) []byte {
		toAppend := []byte(strings.Join([]string{key, value}, " "))
		log.Println(keyRegexp.String())
		if keyRegexp.Match(b) {
			return keyRegexp.ReplaceAllLiteral(b, toAppend)
		}

		return []byte(fmt.Sprintf("%s\n%s", strings.TrimRight(string(b), "\n"), toAppend))
	}
	s.modifications = append(s.modifications, modifyFunc)
}

// Commit is a function to apply the SSHD config modifications made by Set to
// config file and test whether the resulting file is valid. The check is
// performed with 'sshd -t'. If the check fails, then the file is reverted to
// the original before returning the error.
func (s *SSHDConfig) Commit() error {
	original, err := ioutil.ReadFile(s.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read SSHD config at %s: %w", s.ConfigPath, err)
	}
	final := original
	for _, f := range s.modifications {
		final = f(final)
	}

	if bytes.Equal(final, original) {
		return nil
	}

	err = ioutil.WriteFile(s.ConfigPath, final, 0644)
	if err != nil {
		return fmt.Errorf("failed to modify SSHD config: %w", err)
	}

	err = s.testConfig()
	if err != nil {
		cause := fmt.Errorf("verification of modified SSHD config failed: %w", err)

		err := ioutil.WriteFile(s.ConfigPath, original, 0644)
		if err != nil {
			return fmt.Errorf(
				"%v\n%v",
				cause.Error(),
				fmt.Sprintf("failed to revert previous SSHD config (MANUAL FIX NEEDED): %v", err),
			)
		}

		return cause
	}

	return nil
}
