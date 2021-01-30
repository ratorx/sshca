package sshd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"
)

var hostkeyFailCases = [][]byte{
	[]byte("No matching private key for certificate"),
	[]byte("Could not load host certificate"),
}

// Represents a SSHD config modification. Replaces all matches of LineRegexp
// with with the key value pair (in SSHD format). If no matches, it appends to
// the end of the file.
type modification struct {
	LineRegexp *regexp.Regexp
	Key string
	Value string
}

// Apply a modification to a byte array.
func (m modification) Apply(b []byte) []byte {
		toAppend := bytes.Join([][]byte{[]byte(m.Key), []byte(m.Value)}, []byte(" "))
		if m.LineRegexp.Match(b) {
			return m.LineRegexp.ReplaceAllLiteral(b, toAppend)
		}

		return bytes.Join([][]byte{bytes.TrimRight(b, "\n"), toAppend}, []byte("\n"))
}

// Modifier provides a safe wrapper to modify SSHD configuration. Changes are
// verified before being commited. If verification fails, the original file is
// restored.
type Modifier struct {
	ConfigPath    string
	modifications []modification
}

func (s *Modifier) testConfig() error {
	cmd := exec.Command("sshd", "-t")
	_, stderr, err := checkedRun(cmd)
	if err != nil {
		return err
	}
	// Extra test cases - sshd -t returns 0 for these but they are problematic.
	for _, failCase := range hostkeyFailCases {
		if bytes.Contains(stderr, failCase) {
			return fmt.Errorf("invalid hostkey in sshd config")
		}
	}
	return nil
}

// Set adds a key value pair to the SSHD config. It will leave other config
// lines with the same key and only replace a line if it is exactly the same.
// Calling this function does not apply the change until Commit is called.
func (s *Modifier) Set(key, value string) {
	// Use MustCompile because a failure here indicates a programming error rather
	// than input error
	lineRegexp := regexp.MustCompile(fmt.Sprintf("(?m)^#?%s %s.*$", regexp.QuoteMeta(key), regexp.QuoteMeta(value)))
	s.modifications = append(s.modifications, modification{lineRegexp, key, value})
}

// SetUnique sets a unique key in the SSHD config. This means that any other
// use of the key, even with a different value will be replaced. SetUnique
// expects that there is at most 1 use of the key in the SSHD config (i.e. the
// key is unique in the existing SSHD config). Calling this function does not
// apply the change until Commit is called.
func (s *Modifier) SetUnique(key, value string) {
	// Use MustCompile because a failure here indicates a programming error rather
	// than input error
	lineRegexp := regexp.MustCompile(fmt.Sprintf("(?m)^#?%s.*$", regexp.QuoteMeta(key)))
	s.modifications = append(s.modifications, modification{lineRegexp, key, value})
}

// Commit is a function to apply the SSHD config modifications made by Set to
// config file and test whether the resulting file is valid. The check is
// performed with 'sshd -t'. If the check fails, then the file is reverted to
// the original before returning the error.
func (s *Modifier) Commit() error {
	original, err := ioutil.ReadFile(s.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read SSHD config at %s: %w", s.ConfigPath, err)
	}
	final := original
	for _, m := range s.modifications {
		final = m.Apply(final)
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
	// Successful application, reset modifications so it will work again.
	s.modifications = nil
	return nil
}
