package ca

import (
	"fmt"
	"os"
	"os/exec"
)

func runSSHKeygen(args []string) error {
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("ssh-keygen output:\n")
	if err := cmd.Run(); err != nil {
		// Unwrapping the error is possibly dangerous (might expect to keep using
		// stderr outside the critical section). Explicitly convert to string before
		// returning. May not be strictly necessary, but I CBA to test and find out.
		return fmt.Errorf("ssh-keygen failed: %s", err.Error())
	}
	return nil
}
