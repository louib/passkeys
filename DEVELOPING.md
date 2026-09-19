# Developing

## Known-working WebAuthn settings

The current Linux UHID proof of concept has been tested with Chromium and Firefox using [webauthn.io](https://webauthn.io) and these registration settings:

- Algorithm: `Ed25519` (COSE `-8`) only
- Authenticator attachment: `cross-platform`
- User verification: `discouraged`
- Discoverable credential: `discouraged`
- Attestation: `none`
- Hints: `security-key`, `hybrid`, `client-device`

Credentials are stored only in memory. Keep the authenticator process running between registration and authentication.

## Minimal test

Ensure `/dev/uhid` exists and the current user can open it, then start the authenticator:

```sh
cargo run --features linux-uhid --example uhid_listen
```

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
