package main

import (
	"fmt"
	"strings"

	"github.com/Showmax/go-fqdn"
	"github.com/hashicorp/go-multierror"
	"github.com/ratorx/sshca/ca"
	"github.com/ratorx/sshca/sshd"
)

// SignUserCmd is the command to generate a SSH user certficate for the provided
// public key.
type SignUserCmd struct {
	RPCFlags
	Principals    CommaSeparatedList `arg:"-n,required" help:"principals to authorise the key for (comma-separated)"`
	PublicKeyPath string             `arg:"positional,required" help:"path to the SSH public key"`
}

// Validate implementation for Command
func (s SignUserCmd) Validate() error {
	return s.RPCFlags.Validate()
}

// Run implementation for Command
func (s SignUserCmd) Run() error {
	client, err := s.RPCFlags.MakeClient()
	if err != nil {
		return err
	}

	_, err = generateCertificate(client, s.PublicKeyPath, s.Principals.Items, ca.UserCertificate, !s.RPCFlags.Local)
	return err
}

// SignHostCmd represents the command that signs all the host keys for the
// current host. It uses the hostname (short and long) as the default
// principals.
type SignHostCmd struct {
	RPCFlags
	SSHDConfigPath string             `default:"/etc/ssh/sshd_config" help:"path to the sshd_config"`
	Principals     CommaSeparatedList `arg:"-n" help:"extra principals for the host keys (comma-separated)"`
}

func (s SignHostCmd) findPublicKeys() ([]string, error) {
	privateKeys, err := sshd.Lookup(s.SSHDConfigPath, "HostKey")
	if err != nil {
		return nil, fmt.Errorf("failed to find host keys for %w", err)
	}
	publicKeys := make([]string, 0, len(privateKeys))
	for _, privateKey := range privateKeys {
		publicKeys = append(publicKeys, privateKey+".pub")
	}

	return publicKeys, nil
}

func (s SignHostCmd) getPrincipals() ([]string, error) {
	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	// Use a map to put unique principals into the final slice
	principals := make(map[string]bool, 2+len(s.Principals.Items))
	principals[hostname] = true
	principals[strings.Split(hostname, ".")[0]] = true
	for _, principal := range s.Principals.Items {
		principals[principal] = true
	}
	principalsSlice := make([]string, 0, len(principals))
	for principal := range principals {
		principalsSlice = append(principalsSlice, principal)
	}

	return principalsSlice, nil
}

// Validate implementation for Command
func (s SignHostCmd) Validate() error {
	return s.RPCFlags.Validate()
}

// Run implementation for Command
func (s SignHostCmd) Run() error {
	client, err := s.RPCFlags.MakeClient()
	if err != nil {
		return err
	}

	principals, err := s.getPrincipals()
	if err != nil {
		return fmt.Errorf("failed to get principals: %w", err)
	}

	publicKeyPaths, err := s.findPublicKeys()
	if err != nil {
		return fmt.Errorf("failed to get find public keys: %w", err)
	}
	fmt.Printf("found %v host keys\n", len(publicKeyPaths))

	sshdModifier := sshd.Modifier{ConfigPath: s.SSHDConfigPath}
	for _, keyPath := range publicKeyPaths {
		certPath, certErr := generateCertificate(client, keyPath, principals, ca.HostCertificate, !s.RPCFlags.Local)
		if certErr == nil {
			sshdModifier.Set("HostCertificate", certPath)
		} else {
			fmt.Println(certErr)
			err = multierror.Append(err, certErr)
		}
	}

	err = sshdModifier.Commit()
	if err != nil {
		return fmt.Errorf("failed to modify SSHD config to enable host certificates")
	}

	return err
}
