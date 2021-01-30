package sshd

import (
	"bytes"
	"fmt"
	"os/exec"
)

// checkedRun is a wrapper around exec.Cmd.Run which captures both Stdout and
// Stderr and possibly returns them based on the exit code.
func checkedRun(cmd *exec.Cmd) ([]byte, []byte, error) {
	if cmd.Stdout != nil {
		return nil, nil, fmt.Errorf("Stdout can't be set")
	}

	if cmd.Stderr != nil {
		return nil, nil, fmt.Errorf("Stderr can't be set")
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), stderr.Bytes(), nil
	}

	switch err := err.(type) {
	case *exec.ExitError:
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("command %q failed with exit code %v - stderr:\n%s", cmd, err.ExitCode(), stderr.Bytes())
	default:
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("failed to execute %q: %w", cmd, err)
	}
}
