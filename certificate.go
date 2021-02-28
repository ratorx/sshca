package main

import (
	"fmt"
	"os"
	"os/user"
	"path"
	"regexp"
	"strings"

	"github.com/ratorx/sshca/ca"
)

var (
	hostKeyRegexp = regexp.MustCompile("^ssh_host_([^_]+)_key.pub$")
	userKeyRegexp = regexp.MustCompile("^id_([^_]+).pub$")
)

// keyIDFromPath attempts to extract the type of key from the path, falling back
// the key's basename. The key is not inspected directly, because the actual
// type of key is not useful as an ID if it's not the default key of that type.
// E.g. id_rsa.pub can be well-identified as rsa, but gcloud.pub can't, even if
// the underlying key is rsa.
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

// getCertificateIdentity generates the identity of the certificate based on the
// host (and user, depending on the certificate) making the request.
func getCertificateIdentity(keyPath string, certType ca.CertificateType) (string, error) {
	certIdentityComponents := make([]string, 0, 3)

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get system hostname: %w", err)
	}
	// Use short hostname for identity
	// On OpenBSD os.Hostname returns the long hostname
	hostname = strings.Split(hostname, ".")[0]
	certIdentityComponents = append(certIdentityComponents, hostname)

	// Append username if it's a user certificate
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

	args.PublicKey, err = ca.NewPublicKey(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read public key at %s: %w", publicKeyPath, err)
	}

	if printRequest {
		fmt.Println(args)
	}

	reply, err := client.SignPublicKey(args)
	if err != nil {
		return "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	certPath := getCertificatePath(publicKeyPath)
	fmt.Printf("writing certificate to %s\n", certPath)

	err = reply.Certificate.WriteFile(certPath, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to write certificate to disk: %w", err)
	}

	return certPath, err
}
