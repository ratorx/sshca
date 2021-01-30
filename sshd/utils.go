package sshd

import (
	"bytes"
	"fmt"
	"os/exec"
)

func checkedRun(cmd *exec.Cmd) ([]byte, error) {
	if cmd.Stdout != nil {
		return nil, fmt.Errorf("Stdout can't be set")
	}

	if cmd.Stderr != nil {
		return nil, fmt.Errorf("Stderr can't be set")
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}

	switch err := err.(type) {
	case *exec.ExitError:
		return stdout.Bytes(), fmt.Errorf("command %q failed with exit code %v - stderr:\n%s", cmd, err.ExitCode(), stderr.Bytes())
	default:
		return stdout.Bytes(), fmt.Errorf("failed to execute %q: %w", cmd, err)
	}
}
