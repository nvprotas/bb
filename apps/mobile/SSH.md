# Android SSH connections

This checkout adds Android-only SSH access to an already running bb server.
Save several SSH hosts in Settings → Servers → Add server → Connect over SSH.
Only the selected host has an active tunnel. Direct and bb connect profiles
remain available.

## Setup

The SSH account must allow TCP forwarding to the address where bb listens.
The default destination is `127.0.0.1:38886` on the SSH server. Keep bb bound
to loopback. The application does not install or start bb.

Enter the SSH hostname, SSH port, username, destination, and a label. Import an
OpenSSH, PEM, or PuTTY private key through the document picker, or choose
"Paste private key text" and paste the key from the clipboard. The key must be
no larger than 64 KiB; the copied cache file is deleted after reading, and the
pasted text is cleared from the form once the key is accepted. The application
does not clear the system clipboard. The application
encrypts the imported key with an Android Keystore key and stores it in its
internal no-backup directory. Saved profile JSON contains a key reference.

After selecting a host, enter its key passphrase or leave the field blank for
an unencrypted key. Passphrases are retained in memory for reconnecting this
activation and discarded when switching profiles. They are not saved to disk.

For an unknown server, compare the displayed SHA-256 fingerprint with an
independently verified host key. Confirming stores the full host public key
before SSH authentication proceeds. A changed key blocks the connection. To
replace trust, verify the new key independently, remove the profile and add it
again. Removing a profile deletes its imported private key when no profile
still references it.

## Transport and multiple hosts

Each profile receives a persistent address from `127.64.0.0/10`. Address
allocation is serialized and persisted independently of the profile index;
deleting a profile does not return its address to the allocator. The native
listener binds to that address on port `38886`. It never binds to a wildcard
address and never falls back to another port when the port is occupied.

The HTTP SDK, native realtime socket, and WebView share the forwarded URL.
The saved `ssh://` URL is a logical connection descriptor, not an HTTP API URL.
Readiness requires successful `/health` and `/api/v1/system/config` probes.
The page receives the existing `direct` native-shell profile mode for
compatibility with servers that predate this client; no new server protocol is
required for normal SSH access.

Distinct IP hosts separate host cookies, and distinct origins separate browser
storage. A stable port keeps the origin unchanged across reconnects. Query
clients belong to profile IDs. The last visited path is saved per SSH profile;
existing web-app draft persistence continues using that profile's origin.
Cookie and storage separation is by IP host and origin; real WebView
isolation still requires device verification.

## Tunnel secret

Other Android apps can connect to loopback, and the bb server trusts loopback
requests. The native listener therefore never forwards raw connections. Each
opened tunnel generates a 32-byte `SecureRandom` secret (URL-safe base64). For
every accepted TCP connection the listener reads the first HTTP request head
(at most 32 KiB, 5-second deadline) and forwards the connection only if it
carries the secret in a `bb_ssh_tunnel` cookie or an `X-BB-Tunnel-Secret`
header (constant-time comparison). Other connections are closed without
reaching the SSH channel. Only the active tunnel's secret is accepted; it is
discarded on close.

The native module stores the cookie (`HttpOnly`, path `/`) for the tunnel host
in Android `CookieManager` before the tunnel is reported open and removes it
on close. React Native `fetch`, the native realtime WebSocket and the WebView
all read that cookie jar, so the SDK client, realtime socket, page requests and
page WebSockets carry it automatically. The readiness probe sends the header
explicitly. Clearing website data restores the cookie. The secret is not
stripped from forwarded requests. Only the first request of a connection is
checked; later requests on an authenticated keep-alive connection are not.
Remaining exposure: a process that can read this app's memory or cookie store.

Switching hosts cancels pending work, disposes the old SDK/realtime client, and
closes the old listener/session. Late successful results are closed. The app
closes the tunnel in the background and reopens it on returning to the
foreground. Network failures after an established connection receive at most
three retries with 1, 2, and 4 second delays. Authentication and host-key errors
require user action. Agents continue on the server while the phone is
disconnected.

Dead links are detected with SSH keepalive requests every 15 seconds; three
unanswered requests disconnect the session (about 45-60 seconds). The native
module also closes the tunnel when the Android default network is lost or
changes (for example Wi-Fi to LTE), so the controller's reconnect starts
immediately. A transport disconnect notification closes the tunnel without polling.

Native SSH connect/key-exchange, authentication and forwarding stages have
15-second deadlines. Host-key confirmation allows 60 seconds, separately from
the connection deadline. Each bb HTTP probe has an 8-second deadline and can
be cancelled.

## Push notifications

SSH registration uses the active tunnel URL; disconnecting preserves existing
registrations. Push delivery uses the existing server/Expo mechanism, not the
SSH tunnel. This checkout's push sender includes the subscription ID so a
notification tap can identify the saved host even when its tunnel is closed.
Older ambiguous notifications with loopback server hints are not routed to a
guessed SSH host. Push delivery and taps require separate device checks.

## Native integration

`modules/bb-ssh` is a local Expo module discovered by Expo autolinking. Its
Kotlin sources survive `expo prebuild --clean`. It uses SSHJ `0.40.0`,
Bouncy Castle `1.80` under a separate provider name, and an SLF4J no-op backend.
The existing Android cleartext setting permits loopback HTTP; remote traffic
is carried by SSH.

The TypeScript native API exposes key import/deletion, tunnel open/close,
host-key confirmation, cancellation, and state events. The lifecycle
controller uses a dependency-injected `SshTransport`, allowing callers to
exercise the same connection path programmatically. Existing bb CLI commands
operate on the connected server; mobile profiles and private keys live on the
phone, not in the server CLI's configuration.

Not included: iOS SSH, password authentication, bastion chains, agent
forwarding, SFTP, server installation, or a persistent Android background
service.

## Verification on another machine

Do not run these builds or heavy checks on the current development machine.
On a build machine with the repository's Node/pnpm versions, JDK 17 and Android
SDK/build tools installed, run from the repository root:

```bash
pnpm install --frozen-lockfile
pnpm exec turbo run typecheck test lint --filter=@bb/mobile
pnpm mobile:apk:dev
adb install -r apps/mobile/build-output/bb-dev.apk
```

The build regenerates the ignored Android project and includes the local SSH
module. Use two independently running test servers. Check:

- unknown, accepted, rejected and changed host keys;
- encrypted and unencrypted keys, wrong passphrase, and invalid key files;
- unavailable bb, forbidden forwarding and occupied local port;
- WebView navigation, mutations, thread streaming and terminal;
- A → B → A during pending connection and after a completed connection;
- separate cookies, local/session storage, cached data and drafts on A and B;
- background/foreground, Wi-Fi/LTE switching, interruption and recovery;
- downloads, previews, push registration/delivery/taps and profile deletion.

As of this implementation, an earlier mobile run passed 342 tests and lint
reported no errors. Some final recovery and compatibility edits were made
after that run and have not been rerun. Expo Android prebuild succeeded. The
Kotlin module compiled against real Android/SSHJ APIs with temporary Expo
stubs; a complete Gradle build, APK and physical-device verification remain
pending. The Gradle attempts stopped before this module compiled.
