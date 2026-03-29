# SplitSig Signer

Sign Nostr events with your Lightning wallet. No extension, no seed phrase.

Your private key is derived locally in the browser from your wallet's LNURL-auth signature + a random nonce. The server never sees your nsec.

```
nsec = SHA256(ecdsa_signature || nonce)
```

## How it works

1. Scan a QR code with your Lightning wallet (LNURL-auth)
2. Your wallet signs a challenge — the server stores the signature
3. Your browser combines the signature with a local random nonce
4. `SHA256(sig + nonce)` = your Nostr private key
5. Sign events, copy your npub, download a recovery kit

The server has the signature but not the nonce. Your browser has both but the key only lives in session memory. The recovery kit has the nonce but not the signature. Nobody has all the pieces except your browser, right now.

## Quick start

```bash
# Build
cd frontend && npm install && npm run build && cd ..
go build -o signer ./cmd/signer/

# Run
SIGNER_FRONTEND_DIR=frontend/dist ./signer

# Open http://localhost:8080
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGNER_PORT` | `8080` | HTTP port |
| `SIGNER_BASE_URL` | `http://localhost:$PORT` | Public URL (for LNURL callback) |
| `SIGNER_FRONTEND_DIR` | (none) | Path to frontend/dist to serve SPA |

## Recovery

Download the recovery kit (JSON file with your nonce). To restore your key on a new device:

1. Import the recovery kit
2. Sign in with the same Lightning wallet
3. Same wallet + same nonce = same nsec

## Tech

- **Backend**: Go (LNURL-auth server, no database)
- **Frontend**: Vanilla TypeScript, Vite, ~40KB
- **Crypto**: `@noble/curves` (Schnorr), `@noble/hashes` (SHA256)
- **Protocol**: [SplitSig NIP-XX](https://github.com/Antisys/splitsig/blob/master/NIP-XX.md)

## License

GPL-3.0
