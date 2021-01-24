package main

import (
	"fmt"
	"net"
	"net/rpc"

	"github.com/alexflint/go-arg"
	"github.com/ratorx/sshca/ca"
)

// ServerCmd represents the command that runs the SSH CA server.
type ServerCmd struct {
	Addr string `arg:"positional,required" help:"TCP address to listen on"`
	PrivateKeyPath string `arg:"-s,required" help:"SSH CA private key path"`
	PublicKeyPath string `arg:"-p" help:"SSH CA public key path (optional, inferred from private key path)"`
}

func (s *ServerCmd) Run() error {
	caRPCServer, err := ca.NewServer(s.PrivateKeyPath, s.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to local SSH CA RPC server: %w", err)
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

type args struct {
	Trust *TrustCmd `arg:"subcommand:trust" help:"trust the remote CA for user and host authentication"`
	SignKey *SignUserCmd `arg:"subcommand:sign_user" help:"generate a user certficate for a public key"`
	SignHost *SignHostCmd `arg:"subcommand:sign_host" help:"generate and configure certificates for all the host keys"`
	Server *ServerCmd `arg:"subcommand:server" help:"run as the SSH CA RPC server"`
}

func (args) Description() string {
	return "CLI tool for easily using SSH certificate authorities"
}

func main() {
	var args args
	var err error
	p := arg.MustParse(&args)
	switch {
	case args.Trust != nil:
		err = args.Trust.Run()
	case args.SignKey != nil:
		err = args.SignKey.Run()
	case args.SignHost != nil:
		err = args.SignHost.Run()
	case args.Server != nil:
		err = args.Server.Run()
	}
	if err != nil {
		p.Fail(err.Error())
	}
}