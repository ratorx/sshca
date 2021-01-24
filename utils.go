package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"strings"
)

var hostKeyRegexp = regexp.MustCompile("^ssh_host_([^_]+)_key.pub$")
var userKeyRegexp = regexp.MustCompile("^id_([^_]+).pub$")

// CommaSeparatedList represents a comma-separated list passed into the command
// line.
type CommaSeparatedList struct {
	Items []string
}

// UnmarshalText converts the bytes received on the command line into a
// CommaSeparatedList
func (csl *CommaSeparatedList) UnmarshalText(b []byte) error {
	csl.Items = strings.Split(string(b), ",")
	return nil
}


func runCommand(cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	switch err := err.(type) {
	case *exec.ExitError:
		return fmt.Errorf("command %q failed with exit code %v - command log:\n%s", cmd, err.ExitCode(), out)
	default:
		return fmt.Errorf("failed to execute %q: %w", cmd, err)
	}
}

func appendIfNotPresent(filename string, toAppend []byte) error {
	contents, _ := ioutil.ReadFile(filename)

	if strings.Contains(string(contents), string(toAppend)) {
		return nil
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("unable to open %s for appending: %w", filename, err)
	}

	_, err = f.Write(toAppend)
	if err != nil {
		return fmt.Errorf("failed to append to %s: %w", filename, err)
	}

	return nil
}

func keyIDFromPath(keyPath string) string {
	keyFile := path.Base(keyPath)

	// Identify common key types by filename and return that
	// Assumption is that there is only 1 default key of a given type and default
	// types are named consistently everywhere.
	for _, re := range []*regexp.Regexp{hostKeyRegexp, userKeyRegexp} {
		if matches := re.FindStringSubmatch(keyFile); matches != nil {
			return matches[1]
		}
	}

	// Otherwise return the name of the key
	return strings.TrimSuffix(keyFile, ".pub")
}

func getCertificateIdentity(keyPath string, isHostKey bool) (string, error) {
	certIdentityComponents := make([]string, 0, 3)

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get system hostname: %w", err)
	}
	certIdentityComponents = append(certIdentityComponents, hostname)

	// Prepend username if it's a user certificate
	if !isHostKey {
		userStruct, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("failed to get name of current user: %w", err)
		}
		certIdentityComponents = append(certIdentityComponents, userStruct.Username)
	} else {
		certIdentityComponents = append(certIdentityComponents, "host")
	}

	certIdentityComponents = append(certIdentityComponents, keyIDFromPath(keyPath))

	return strings.Join(certIdentityComponents, "_"), nil
}
