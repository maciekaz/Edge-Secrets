# esecrets

Command-line client for [Edge Secrets](https://github.com/maciekaz/edge-secrets)
— self-hosted, zero-knowledge sharing of passwords, files and links running on
Cloudflare Workers.

This talks to **your own deployment**. It is not a hosted service, and there is
no default server to send anything to.

```bash
npx esecrets put
```

![Creating a secret, uploading a file and shortening a link with the esecrets CLI](https://raw.githubusercontent.com/maciekaz/edge-secrets/master/docs/media/esecrets.gif)

---

## Install

Node.js 20+, plus [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
for signing in:

```bash
npm install -g esecrets      # or just use npx
brew install cloudflared     # winget install --id Cloudflare.cloudflared
```

You do not need a Cloudflare account — `cloudflared access login` authenticates
you as an end user against the Access policy on your deployment, with your own
identity provider.

## Use

```bash
esecrets config add work secrets.example.com
esecrets login

esecrets put                          # prompts, encrypts locally, link to clipboard
esecrets put --generate eff --ttl 4h
esecrets ls                           # what you sent, and whether it was opened
esecrets rm <id>

esecrets file report.pdf --ttl 48h --limit 3
esecrets file dump.sql --e2ee
esecrets link https://example.com/long/path --max-clicks 25
```

Encryption happens here, before anything leaves the machine — the same Argon2id
parameters and AES-GCM envelope the browser client uses, so a secret made in the
terminal opens in the browser and the other way round.

Secrets are read from a hidden prompt or stdin, never from a command-line
argument. On an interactive terminal the finished link goes to your clipboard
rather than the screen, because a link carries the passphrase after the `#` and
would otherwise sit in your scrollback.

**[Full documentation →](https://github.com/maciekaz/edge-secrets/blob/master/docs/cli.md)**

## License

MIT
