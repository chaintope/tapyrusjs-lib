# Integration tests

These tests build transactions with this library, hand them to a real Tapyrus
node, and check that the node accepts them. They are the only tests that catch
a rule the library gets wrong but the unit tests are happy with — the txid an
outpoint refers to, the value of `nFeatures`, the shape of a coloured script.

They are **not** part of `npm test`. Run them on purpose:

```sh
docker compose -f docker-compose.integration.yml up -d
npm run integration
docker compose -f docker-compose.integration.yml down
```

The node listens on `127.0.0.1:12382`. If nothing is listening there, every
test that needs the node fails with a message saying so rather than hanging.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `TAPYRUS_RPC_URL` | `http://127.0.0.1:12382` | Where the node's JSON-RPC is |
| `TAPYRUS_RPC_USER` | `user` | Matches `rpcuser` in `tapyrus.conf` |
| `TAPYRUS_RPC_PASS` | `pass` | Matches `rpcpassword` in `tapyrus.conf` |
| `TAPYRUS_SIGNER_WIF` | `cUJN5RVz…N7Dd4` | The key that signs generated blocks |

## Why a key sits in the repository

Tapyrus has no proof of work. Every block carries a signature from the
aggregate key the chain was created with, so `generatetoaddress` takes that
key as an argument. The genesis block in `docker-compose.integration.yml` and
the WIF in `_regtest.ts` are the pair tapyrus-core publishes in
`doc/docker_image.md` as its dev mode example. They open this throwaway chain
and nothing else.

To use a different pair, generate a matching genesis block and set both:

```sh
docker run tapyrus/tapyrusd:v0.7.2 tapyrus-genesis -dev \
  -signblockpubkey=<public key> \
  -signblockprivatekey=<WIF>
```

## Starting from scratch each time

`docker compose down` deletes the chain, so every run starts at the same height
with an empty wallet. Nothing in the tests requires a fresh chain — each one
funds a newly generated key, so the colour identifiers it derives are new every
time — but a chain that keeps growing makes a failure harder to read, and the
entrypoint ignores `GENESIS_BLOCK_WITH_SIG` once a genesis file exists, so a
kept volume would outlive a change to the genesis block.

## Running against a node you already have

Point `TAPYRUS_RPC_URL` at it. The node must run in dev mode with a wallet
that `getnewaddress` and `sendtoaddress` work on, and you must pass the
matching signer key in `TAPYRUS_SIGNER_WIF`.
