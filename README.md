# SSHCA - CLI tool for easily using SSH certificate authorities.

Problems I have with ssh-keygen + bash scripts and various other alternatives:
* Need to run things on both requestor and CA hosts to create certificates (unavoidable, but I can try to make it nicer).
* SSHD needs to be configured. It's not impossible to do it in bash, but a bit annoying to do idempotently.
* Ansible etc. are nice for idempotent file changes, but are large dependencies.
* ssh-cert-authority etc. are quite complex and designed for scalability. I'm fine with manually verifying each certificate request, I just want to automate all the other bits.

Go can generate a single static binary for multiple OSes that I can just `wget` and use. Integration with GitHub actions lets me automate building new binaries. Easy download URL: https://gh.ree.to/sshca.{platform}.{arch}.

## How does it work?

There are 3 operations that a host might want to perform:
* `trust` - Trust a SSH CA public key for user and host authentication. This involves setting `/etc/ssh/ssh_known_hosts` and `TrustedUserCAKeys` in the SSHD config. (TODO: try harder to not clobber existing options).
* `sign_host` - Finds and signs all the host keys for this system. Adds the required `HostCertificate` lines to the config. Clobbering existing certificates is unavoidable (because each key only supports 1 certificate).
* `sign_user` - Generates a user certificate for the provided public key.

In addition, there is a `server` command that needs to be run on the host with access to the CA private key. This serves a simple Go RPC over TCP. There is no authentication on this, but user confirmation is needed before the server generates the certificate. Thus, the server should not be exposed to the internet, but briefly exposing it to a LAN or tunneling it over SSH should be fine.

In the special case where the client and server are on the same device, there is a special mode of operation (`--local`) that bypasses exposing the RPC with TCP. In this case, user confirmation is disabled.

This script never reads or writes any private keys. The underlying certificate generation is handled by ssh-keygen.

## Example Workflow

On the host with access to CA:
```
sshca server -s /etc/ssh/ssh_ca_key localhost:5000
```

In a separate terminal:
```
ssh -L 5000:localhost:5000 example.com sshca trust -r localhost:5000
ssh -L 5000:localhost:5000 example.com sshca sign_host -r localhost:5000
ssh -L 5000:localhost:5000 example.com sshca sign_user -r localhost:5000 ~/.ssh/id_ed25519.pub
```

The first couple of commands probably need root access because they modify SSHD config. It's not recommended to expose the sshca server directly to the internet, but it might be necessary if SSH access is not available. It should be alright if you have to (especially for brief periods), because certificate generation requires user confirmation.

## TODO
* Better unit test coverage
* Support more flags to ssh-keygen:
  * Validity
  * Certificate options
  * Serial numbers
* Better audit logging
* Certificate revocation
* 2FA
