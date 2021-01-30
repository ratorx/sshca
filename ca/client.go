package ca

import (
	"net/rpc"
)

const (
	// ServerName is the name that the CA client expects to find the server at.
	ServerName             = "CA"
	getCAPublicKeyEndpoint = ServerName + "." + "GetCAPublicKey"
	signPublicKeyEndpoint  = ServerName + "." + "SignPublicKey"
)

// Client wraps rpc.Client and provides functions to call the SSH CA RPCs.
type Client struct {
	*rpc.Client
}

// GetCAPublicKey represents the GetCAPublicKey RPC call
func (c *Client) GetCAPublicKey() (*PublicKeyReply, error) {
	publicKey := new(PublicKeyReply)
	err := c.Call(getCAPublicKeyEndpoint, struct{}{}, publicKey)
	return publicKey, err
}

// SignPublicKey represents the SignPublicKey RPC call
func (c *Client) SignPublicKey(args SignArgs) (*SignReply, error) {
	signReply := new(SignReply)
	err := c.Call(signPublicKeyEndpoint, args, signReply)
	return signReply, err
}
