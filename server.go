package main

import (
	"fmt"
	"net"
	"net/rpc"

	"github.com/ratorx/sshca/ca"
)

// ServerCmd is the command that starts a RPC server for CA operations
// on a TCP Address.
type ServerCmd struct {
	// TODO: Work out nice way to validate the address
	Addr             string `arg:"positional,required" help:"TCP address to listen on"`
	PrivateKeyPath   string `arg:"-s,--private,required" placeholder:"PRIVATE_KEY_PATH" help:"SSH CA private key path"`
	PublicKeyPath    string `arg:"-p,--public" placeholder:"PUBLIC_KEY_PATH" help:"SSH CA public key path (optional, inferred from private key path)"`
	SkipConfirmation bool   `arg:"--skip-confirmation,-q" help:"Skip confirmation for public key signing requests"`
}

// Validate implementation for Command
func (s ServerCmd) Validate() error {
	return nil
}

// Run implementation for Command
func (s ServerCmd) Run() error {
	caRPCServer, err := ca.NewServer(s.PrivateKeyPath, s.PublicKeyPath, s.SkipConfirmation)
	if err != nil {
		return fmt.Errorf("failed to initialize SSH CA RPC server: %w", err)
	}

	server := rpc.NewServer()
	server.RegisterName(ca.ServerName, &caRPCServer)

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.Addr, err)
	}
	server.Accept(listener)
	return nil
}
