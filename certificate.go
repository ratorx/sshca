package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"regexp"
	"strings"

	"github.com/ratorx/sshca/ca"
)

var hostKeyRegexp = regexp.MustCompile("^ssh_host_([^_]+)_key.pub$")
var userKeyRegexp = regexp.MustCompile("^id_([^_]+).pub$")

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


func getCertificateIdentity(keyPath string, certType ca.CertificateType) (string, error) {
	certIdentityComponents := make([]string, 0, 3)

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get system hostname: %w", err)
	}
	certIdentityComponents = append(certIdentityComponents, hostname)

	// Prepend username if it's a user certificate
	if !certType {
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

func getCertificatePath(keyPath string) string {
	return fmt.Sprintf("%s-cert.pub", strings.TrimSuffix(keyPath, ".pub"))
}

// generateCertificate creates a certificate for the public key at publicKeyPath
// and writes it to the expected place (key.pub generates key-cert.pub). Returns
// the path that the certificate was written at.
func generateCertificate(client *ca.Client, publicKeyPath string, principals []string, certType ca.CertificateType, printRequest bool) (string, error) {
	var err error
	args := ca.SignArgs{CertificateType: certType, Principals: principals}

	args.Identity, err = getCertificateIdentity(publicKeyPath, certType)
	if err != nil {
		return "", fmt.Errorf("failed to generate certificate identity: %w", err)
	}

	args.PublicKey, err = ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read public key at %s: %w", publicKeyPath, err)
	}

	id, err := args.Identify()
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	if printRequest {
		fmt.Println(id)
	}

	reply, err := client.SignPublicKey(args)
	if err != nil {
		return "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	certPath := getCertificatePath(publicKeyPath)
	fmt.Printf("writing certificate to %s\n", certPath)

	err = ioutil.WriteFile(certPath, reply.Certificate, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to write certificate to disk: %w", err)
	}

	return certPath, err
}
