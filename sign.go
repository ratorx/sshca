package main

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"

	"github.com/Showmax/go-fqdn"
	"github.com/hashicorp/go-multierror"
	"github.com/ratorx/sshca/ca"
)

func generateCertificate(client *ca.Client, publicKeyPath string, principals []string, isHostKey bool) error {
	var err error
	args := ca.SignArgs{IsHostKey: isHostKey, Principals: principals}

	args.Identity, err = getCertificateIdentity(publicKeyPath, isHostKey)
	if err != nil {
		return fmt.Errorf("failed to generate certificate identity: %w", err)
	}

	args.PublicKey, err = ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key at %s: %w", publicKeyPath, err)
	}

	fmt.Printf("request signature with identity %s\n", args.Identity)

	reply, err := client.SignPublicKey(args)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	certPath := fmt.Sprintf("%s-cert.pub", strings.TrimSuffix(publicKeyPath, ".pub"))
	fmt.Printf("writing certificate to %s\n", certPath)

	err = ioutil.WriteFile(certPath, reply.Certificate, 0600)
	if err != nil {
		return fmt.Errorf("failed to write certificate to disk: %w", err)
	}

	return err
}


// SignUserCmd is the command to sign a public key with the CA with the given
// arguments.
type SignUserCmd struct {
	RPCFlags
	Principals CommaSeparatedList `arg:"-n,required" help:"principals to authorise the key for (comma-separated)"`
	PublicKeyPath string `arg:"positional,required" help:"path to the SSH public key"`
}

// Run runs the SignUserCmd command
func (s *SignUserCmd) Run() error {
	client, err := s.RPCFlags.makeClient()
	if err != nil {
		return err
	}

	return generateCertificate(client, s.PublicKeyPath, s.Principals.Items, false)
}

// SignHostCmd represents the command that signs all the host keys for the
// current host. It uses the hostname (short and long) as the default
// principals.
type SignHostCmd struct {
	RPCFlags
	HostKeyDir string `default:"/etc/ssh" help:"directory to search for host keys"`
	Principals CommaSeparatedList `arg:"-n" help:"extra principals for the host keys (comma-separated)"`
}

func (s *SignHostCmd) findPublicKeys() ([]string, error) {
	infos, err := ioutil.ReadDir(s.HostKeyDir)
	if err != nil {
		return nil, fmt.Errorf("unable to read files in %s: %w", s.HostKeyDir, err)
	}

	filenames := make([]string, 0, len(infos))
	for _, info := range infos {
		if hostKeyRegexp.MatchString(path.Base(info.Name())) {
			filenames = append(filenames, path.Join(s.HostKeyDir, info.Name()))
		}
	}

	return filenames, nil
}

func (s *SignHostCmd) getPrincipals() ([]string, error) {
	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	// Use a map to put unique principals into the final slice
	principals := make(map[string]bool, 2 + len(s.Principals.Items))
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

// Run runs the SignHostCmd command
func (s *SignHostCmd) Run() error {
	client, err := s.RPCFlags.makeClient()
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

	for _, keyPath := range publicKeyPaths {
		certErr := generateCertificate(client, keyPath, principals, true)
		if certErr != nil {
			fmt.Println(certErr)
			err = multierror.Append(err, certErr)
		}
	}

	return err
}
