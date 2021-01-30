package main

import (
	"fmt"
	"net"
	"net/rpc"

	"github.com/ratorx/sshca/ca"
)

// RPCFlags are the flags required for RPC that are common across multiple
// commands.
type RPCFlags struct {
	Local            bool   `arg:"-l" help:"run SSH CA operations on the client (exclusive with --remote)"`
	CAPrivateKeyPath string `arg:"-s,--ca-private" placeholder:"PRIVATE_KEY_PATH" help:"SSH CA private key path (only required when --local is set)"`
	CAPublicKeyPath  string `arg:"-p,--ca-public" placeholder:"PUBLIC_KEY_PATH" help:"SSH CA public key path (optional, only used when --local is set)"`
	Remote           string `arg:"-r" help:"remote server for SSH CA operations (exclusive with --local)"`
}

// Validate the flags and arguments that were passed into the command line.
// Ensures that either local or remote operation is selected, and the
// appropriate required flags for each are set.
func (r *RPCFlags) Validate() error {
	if r.Local && r.Remote != "" {
		return fmt.Errorf("both --local and --remote cannot be used at the same time")
	}

	if !r.Local && r.Remote == "" {
		return fmt.Errorf("one of --local or --remote must be used")
	}

	if r.Local && r.CAPrivateKeyPath == "" {
		return fmt.Errorf("--privatekeypath must be set when --local is used")
	}

	return nil
}

// MakeClient creates a new ca.Client based on the RPC Flags. It either returns
// a local client (where the server is run in a goroutine), or a remote
// client that is connected to a TCP RPC server.
func (r *RPCFlags) MakeClient() (*ca.Client, error) {
	err := r.Validate()
	if err != nil {
		return nil, err
	}

	if r.Local {
		return r.makeLocalClient()
	}

	return r.makeRemoteClient()
}

func (r *RPCFlags) makeLocalClient() (*ca.Client, error) {
	left, right := net.Pipe()

	caRPCServer, err := ca.NewServer(r.CAPrivateKeyPath, r.CAPublicKeyPath, true)
	if err != nil {
		return nil, fmt.Errorf("failed to local SSH CA RPC server: %w", err)
	}

	server := rpc.NewServer()
	server.RegisterName(ca.ServerName, &caRPCServer)
	go server.ServeConn(left)

	return &ca.Client{Client: rpc.NewClient(right)}, nil
}

func (r *RPCFlags) makeRemoteClient() (*ca.Client, error) {
	client, err := rpc.Dial("tcp", r.Remote)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server at %s: %w", r.Remote, err)
	}
	return &ca.Client{Client: client}, nil
}
