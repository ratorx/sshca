package main

import (
	"fmt"

	"github.com/alexflint/go-arg"
)

// Command represents a top-level CLI argument
type Command interface {
	// Validate should check the flag values (the struct fields)
	Validate() error
	// Run executes the actual command
	Run() error
}

// ServerCmd represents the command that runs the SSH CA server.
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
	var cmd Command
	p := arg.MustParse(&args)
	switch {
	case args.Trust != nil:
		cmd = args.Trust
	case args.SignKey != nil:
		cmd = args.SignKey
	case args.SignHost != nil:
		cmd = args.SignHost
	case args.Server != nil:
		cmd = args.Server
	}

	// Handle flag validation
	err := cmd.Validate()
	if err != nil {
		p.Fail(err.Error())
	}

	err = cmd.Run()
	if err != nil {
		// TODO: Generate a nice error message
		fmt.Println(err)
	}
}