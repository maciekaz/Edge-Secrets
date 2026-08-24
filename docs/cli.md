# Command-line client

[← Documentation index](README.md)

`esecrets` talks to your own deployment from the terminal. It does the same
client-side encryption the browser does — the same Argon2id parameters, the same
AES-GCM envelope — so a secret created here opens in the browser and vice versa.

---

## Installation

Two pieces: the CLI itself, and `cloudflared`, which handles signing in.

### 1. The CLI

Nothing to install — run it straight from npm:

```bash
npx esecrets put
```

Or keep it around, if you use it often:

```bash
npm install -g esecrets
```

**Node.js 20 or newer** is the only runtime requirement. The package has a
single dependency, `hash-wasm` — the same Argon2id build the Worker serves to
browsers, which is what makes the two sides byte-compatible.

### 2. cloudflared

Signing in needs it, so install it once:

| | |
|---|---|
| macOS | `brew install cloudflared` |
| Windows | `winget install --id Cloudflare.cloudflared` |
| Linux | [packages and binaries](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) |

**You do not need a Cloudflare account.** `cloudflared access login`
authenticates you as an end user against the Access policy on your deployment —
the same sign-in you already do in the browser to reach `/gen`, with your own
identity provider and MFA. It is a different command from `cloudflared tunnel
login`, which is the one that wants dashboard credentials.

If you cannot install it on a particular machine, `ESECRETS_TOKEN` lets you
supply a token from elsewhere; see [Environment](#environment) for the trade-off
that involves.

---

## First run

```bash
esecrets config add work secrets.example.com
esecrets login
esecrets who
```

`config add` stores the deployment URL under a profile name. Add several and
switch with `--profile`, or set a default with `esecrets config default <name>`.

The config file holds **URLs only**. Your token lives in cloudflared's own
cache and expires with the Access session duration your administrator set, so
there is nothing long-lived on disk that this tool put there.

---

## Secrets

```bash
esecrets put                                  # prompts, 24h, one-time read
esecrets put --ttl 1h
esecrets put --generate eff --ttl 4h
esecrets put --bind device --ttl 7d
printf '%s' "$TOKEN" | esecrets put --ttl 15m # from a pipe
esecrets ls                                   # your ledger
esecrets rm <id>                              # revoke
```

Run bare, `put` asks for the value without echoing it, then for a lifetime and
an access mode. Every flag you pass removes the matching question, so a fully
specified command runs without stopping.

**Leaving the secret prompt empty means "generate one".** You then pick a
standard: `nist` (20 characters, 117 bits), `eff` (six words, 77 bits), `bip39`
(twelve words, 132 bits), `legacy` (12 characters with one of each class, 64
bits), `api` (32 random bytes, base64). Those are the same generators, the same
wordlists and the same stated floors as the panel.

The generated value is not printed — it travels inside the link. Add `--show`
if you also need it locally, for example to set it on the system it belongs to.

### Access modes

| `--bind` | Meaning | Maximum lifetime |
|---|---|---|
| `once` (default) | Destroyed on first successful read | 7 days |
| `device` | Tied to the browser profile that opens it first | 30 days |
| `key` | Tied to a hardware security key | 30 days |

The binding happens in the recipient's browser, so creating a bound secret from
the terminal works exactly as it does from the panel.

---

## Files

```bash
esecrets file report.pdf --ttl 48h --limit 3
esecrets file dump.sql --e2ee              # encrypted before it leaves
esecrets file archive.zip --password       # prompts, server-visible
esecrets files                             # usage and stored files
esecrets rm --file <id>
```

Uploads go in 50 MiB parts, four at a time, matching the browser client.

`--e2ee` encrypts locally and uploads ciphertext; the server stores no key
material. It is capped at **150 MiB** by the server, so the CLI refuses larger
files before reading them. Without `--e2ee` the file is stored as-is and the
server can read it — an optional `--password` gates the download but does not
change that, which is why the CLI says so when you use it.

---

## Links

```bash
esecrets link https://example.com/long/path --ttl 1d --max-clicks 25
```

---

## Output, piping and the clipboard

One rule explains the behaviour: **stdout carries the result, stderr carries
everything else.**

On an interactive terminal the finished link goes to your **clipboard** and only
a confirmation appears on screen. A link contains the passphrase after the `#`,
so printing it would leave a working credential sitting in your scrollback for
as long as the window lives.

When output is redirected, the raw link goes to stdout instead, so pipelines
work:

```bash
esecrets put --ttl 1h > link.txt
esecrets ls --json | jq '.[] | select(.status == "pending")'
```

`--print` forces the link onto the screen; `--json` switches stdout to a
machine-readable object; `--no-color` disables colour, as does `NO_COLOR`.

---

## Environment

| Variable | Effect |
|---|---|
| `ESECRETS_URL` | Deployment URL, overriding the configured default |
| `ESECRETS_CONFIG_DIR` | Where to keep `config.json` |
| `ESECRETS_TOKEN` | Use this Access JWT instead of signing in through cloudflared |
| `NO_COLOR` / `FORCE_COLOR` | Colour, off and on |

`ESECRETS_TOKEN` exists for machines where cloudflared cannot be installed. Be
aware of what it gives up: a token obtained through cloudflared is scoped to one
Access application, whereas one you supply is sent to whatever deployment the
current profile points at. The CLI warns each time it uses one.

---

## What this protects, and what it does not

Worth reading once, because two of these are local exposures the tool cannot
remove for you.

- **Secrets never travel through the command line.** Values are read from a
  hidden prompt or from stdin. Passing one as an argument still works, because
  it is occasionally convenient, but it is recorded in your shell history and
  visible in the process list — so the CLI warns and tells you the better form.
- **Links go to the clipboard, not the screen.** That trades scrollback
  exposure for clipboard exposure. Any application running as you can read the
  clipboard; nothing can read it from another machine. If you would rather have
  neither, `--print` into a pipe.
- **The passphrase is always generated, never asked for.** It is ephemeral key
  material that nobody types or remembers, so a human-chosen one could only be
  weaker. `--passphrase-stdin` exists for the rare case of a pre-agreed value.
- **Uploads are read into zeroed buffers, filled completely before sending.** A
  partially filled uninitialised buffer would ship whatever the process happened
  to have in that memory.
- **Plaintext text secrets cannot be wiped from memory.** JavaScript strings are
  immutable and garbage-collected; file plaintext is zeroed after encryption,
  but a string cannot be. This is inherent to the runtime.

Full threat model for the service itself is in [security.md](security.md).

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `cloudflared is required to sign in` | The binary is not in `PATH`. Install it, or supply `ESECRETS_TOKEN` |
| `failed to get app info` | The deployment URL is wrong or unreachable. Check `esecrets config list` |
| Sign-in loops without succeeding | Your identity is not in the Access policy for this application |
| `a one-time secret can live at most 7d` | Longer lifetimes need `--bind device` or `--bind key` |
| `end-to-end encrypted uploads are capped at 150 MiB` | A server-side limit. Upload without `--e2ee`, or split the file |
| Nothing lands on the clipboard | No clipboard helper found. Linux needs `wl-copy` or `xclip`; otherwise use `--print` |

---

## Known gaps

- **Interrupted uploads restart from the beginning.** R2 multipart would allow
  resuming, but the CLI does not yet persist the upload id and part etags.
- **`esecrets logout` removes cloudflared's cached token file directly**,
  because `cloudflared access` has no logout subcommand. It only touches files
  named for your deployment's hostname; the organisation-wide token is left
  alone unless you pass `--all`.
