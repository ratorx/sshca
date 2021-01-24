package main

import (
	"fmt"
)

// TrustCmd represents the command that configures the host to trust the CA for
// user and host authentication.
type TrustCmd struct {
	RPCFlags
}

func (t *TrustCmd) trustAsUserCA(publicKey []byte) error {
	err := appendIfNotPresent("/etc/ssh/trusted_cas", publicKey)
	if err != nil {
		return fmt.Errorf("failed to add key to trusted CAs: %w", err)
	}

	sshdConfig := SSHDConfig{ConfigPath: "/etc/ssh/sshd_config"}
	sshdConfig.Set("TrustedUserCAKeys", "/etc/ssh/trusted_cas", true)
	sshdConfig.Commit()
	if err != nil {
		return fmt.Errorf("unable set TrustedUserCAKeys: %w", err)
	}

	return nil
}

func (t *TrustCmd) trustAsHostCA(publicKey []byte) error {
	err := appendIfNotPresent("/etc/ssh_known_hosts", []byte(fmt.Sprintf("@cert-authority * %s", publicKey)))
	if err != nil {
		return fmt.Errorf("failed to add key to SSH known hosts")
	}

	return nil
}

// Run runs the TrustCmd command
func (t *TrustCmd) Run() error {
	client, err := t.RPCFlags.makeClient()
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