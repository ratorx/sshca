package main

import (
	"fmt"

	"github.com/ratorx/sshca/ca"
	"github.com/ratorx/sshca/sshd"
)

// TrustCmd represents the command that configures the host to trust the CA for
// user and host authentication.
type TrustCmd struct {
	RPCFlags
}

func (t *TrustCmd) trustAsUserCA(publicKey *ca.PublicKey) error {
	err := appendIfNotPresent("/etc/ssh/trusted_cas", publicKey.Marshal())
	if err != nil {
		return fmt.Errorf("failed to add key to trusted CAs: %w", err)
	}

	sshdConfig := sshd.Modifier{ConfigPath: "/etc/ssh/sshd_config"}
	sshdConfig.SetUnique("TrustedUserCAKeys", "/etc/ssh/trusted_cas")
	sshdConfig.Commit()
	if err != nil {
		return fmt.Errorf("unable set TrustedUserCAKeys: %w", err)
	}

	fmt.Printf("trusted public key (fingerprint %s) as authority for user authentication\n", publicKey.Fingerprint())
	return nil
}

func (t *TrustCmd) trustAsHostCA(publicKey *ca.PublicKey) error {
	err := appendIfNotPresent("/etc/ssh_known_hosts", []byte(fmt.Sprintf("@cert-authority * %s", publicKey)))
	if err != nil {
		return fmt.Errorf("failed to add key to SSH known hosts")
	}

	fmt.Printf("trusted public key (fingerprint %s) as authority for host authentication\n", publicKey.Fingerprint())
	return nil
}

// Validate implementation for Command
func (t *TrustCmd) Validate() error {
	return t.RPCFlags.Validate()
}

// Run implementation for Command
func (t *TrustCmd) Run() error {
	client, err := t.RPCFlags.MakeClient()
	if err != nil {
		return err
	}

	publicKeyReply, err := client.GetCAPublicKey()
	if err != nil {
		return fmt.Errorf("failed to fetch public key from server: %w", err)
	}

	err = t.trustAsHostCA(publicKeyReply.CAPublicKey)
	if err != nil {
		return err
	}

	return t.trustAsUserCA(publicKeyReply.CAPublicKey)
}
