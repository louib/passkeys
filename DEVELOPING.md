# Developing

## Known-working WebAuthn settings

The current Linux UHID proof of concept has been tested with Chromium and Firefox using [webauthn.io](https://webauthn.io) and these registration settings:

- Algorithm: `Ed25519` (COSE `-8`) only
- Authenticator attachment: `cross-platform`
- User verification: `discouraged`
- Discoverable credential: `discouraged`
- Attestation: `none`
- Hints: `security-key`, `hybrid`, `client-device`

Credentials are stored only in memory. Keep the selected authenticator process running between registration and authentication.

## Minimal test

Ensure `/dev/uhid` exists and the current user can open it. To test the reference implementation using one local Ed25519 key per credential, run:

```sh
cargo run --features linux-uhid --example uhid_local
```

To test the MPC implementation, run:

```sh
cargo run --features linux-uhid --example uhid_frost
```

The FROST example creates three in-memory participant shares with a threshold of two. Participants 1 and 2 sign normally, while participant 3 is the backup share.

To test automatic use of the backup share, build as your normal user and run the already-built binary as root while marking participant 2 unavailable:

```sh
cargo build --features linux-uhid --example uhid_frost; sudo ./target/debug/examples/uhid_frost --unavailable-participant 2
```

The logs will show the preferred `1+2` pair being replaced automatically by `1+3`. Mark participant 1 unavailable to exercise the `2+3` pair instead.

Open `https://webauthn.io`, apply the settings above, and register. Answer `y` at:

```text
Register this passkey? [y/n]:
```

Then authenticate without restarting the process and answer `y` at:

```text
Authenticate this passkey? [y/n]:
```

When Firefox sees multiple security keys, it first sends a device-selection probe. Select this authenticator by answering `y` at:

```text
Use this authenticator for Firefox? [y/n]:
```

Firefox should then send the real Ed25519 registration request and display the registration prompt above.

Run the automated tests with:

```sh
cargo test --features linux-uhid
```
