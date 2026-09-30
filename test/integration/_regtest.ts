import * as assert from 'assert';
import * as tapyrus from '../..';

const rng = require('randombytes');

const RPC_URL = process.env.TAPYRUS_RPC_URL || 'http://127.0.0.1:12382';
const RPC_USER = process.env.TAPYRUS_RPC_USER || 'user';
const RPC_PASS = process.env.TAPYRUS_RPC_PASS || 'pass';

// The dev mode signer. tapyrus-core publishes this pair in doc/docker_image.md
// as the example for `tapyrus-genesis -dev`, and the genesis block the node
// starts from commits to the matching aggregate public key
// 03af80b90d25145da28c583359beb47b21796b2fe1a23c1511e443e7a64dfdb27d.
// generatetoaddress rejects any other key.
const SIGNER_WIF =
  process.env.TAPYRUS_SIGNER_WIF ||
  'cUJN5RVzYWFoeY8rUztd47jzXCu1p57Ay8V7pqCzsBD3PEXN7Dd4';

const NETWORK = tapyrus.networks.dev;

// Long enough for generatetoaddress on a slow runner, short enough that a
// dropped packet fails before mocha's own timeout.
const RPC_TIMEOUT_MS = 20000;
// Blocks mined to fund the wallet before giving up. Far more than a wallet
// that is credited by them needs; only a wallet that is never paid reaches it.
const MAX_FUNDING_BLOCKS = 500;

/** A spendable output. `value` is satoshi for TPC and a token count otherwise. */
export interface Unspent {
  txId: string;
  vout: number;
  value: number;
  address?: string;
  script?: Buffer;
  token?: string;
}

export interface FetchedOutput {
  value: number;
  address?: string;
  script: Buffer;
  /** 'TPC', or the colour identifier in hex. */
  token: string;
}

export interface FetchedTransaction {
  txId: string;
  txHex: string;
  outs: FetchedOutput[];
}

interface RpcResponse<T> {
  result: T;
  error: { code: number; message: string } | null;
}

/** The fields this harness reads out of getrawtransaction. */
interface RawTransaction {
  txid: string;
  hex: string;
  vout: Array<{
    /** 'TPC', or the colour identifier in hex. */
    token: string;
    /** TPC as a decimal amount; a token as a whole count. */
    value: number;
    scriptPubKey: { hex: string; addresses?: string[] };
  }>;
}

function checkRawTransaction(tx: unknown, txId: string): RawTransaction {
  const raw = tx as RawTransaction;
  if (!raw || typeof raw.hex !== 'string' || !Array.isArray(raw.vout))
    throw new Error(
      `getrawtransaction ${txId} did not answer with a decoded transaction: ` +
        JSON.stringify(tx),
    );
  return raw;
}

function toTpc(satoshi: number): string {
  return (satoshi / 1e8).toFixed(8);
}

function toSatoshi(tpc: number): number {
  return Math.round(tpc * 1e8);
}

let nextRequestId = 0;

class RegtestUtils {
  readonly network: tapyrus.Network = NETWORK;

  private randomAddressCache?: string;
  private minerAddressCache?: string;

  get RANDOM_ADDRESS(): string {
    if (this.randomAddressCache === undefined) {
      this.randomAddressCache = this.randomAddress();
    }
    return this.randomAddressCache;
  }

  async rpc<T>(method: string, params: unknown[] = []): Promise<T> {
    const headers = new Headers();
    headers.set('content-type', 'application/json');
    headers.set(
      'authorization',
      'Basic ' + Buffer.from(`${RPC_USER}:${RPC_PASS}`).toString('base64'),
    );

    let response: Response;
    try {
      response = await fetch(RPC_URL, {
        method: 'POST',
        headers,
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
        body: JSON.stringify({
          jsonrpc: '1.0',
          id: `tapyrusjs-lib-${nextRequestId++}`,
          method,
          params,
        }),
      });
    } catch (err) {
      if ((err as Error).name === 'TimeoutError') {
        throw new Error(
          `${method} did not answer within ${RPC_TIMEOUT_MS}ms. The node at ` +
            `${RPC_URL} is reachable but not responding in time.`,
        );
      }
      throw new Error(
        `Cannot reach a Tapyrus node at ${RPC_URL}. Start one with ` +
          '`docker compose -f docker-compose.integration.yml up -d` ' +
          `(see test/integration/README.md). Cause: ${err}`,
      );
    }

    const text = await response.text();
    let body: RpcResponse<T>;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(
        `${method} returned ${response.status} with a non-JSON body: ${text}`,
      );
    }
    if (body.error) throw new Error(`${method} failed: ${body.error.message}`);
    return body.result;
  }

  async height(): Promise<number> {
    return this.rpc<number>('getblockcount');
  }

  /** Generates `count` blocks, signing each with the dev mode signer. */
  async mine(count: number): Promise<string[]> {
    return this.rpc<string[]>('generatetoaddress', [
      count,
      await this.minerAddress(),
      SIGNER_WIF,
    ]);
  }

  async broadcast(txHex: string): Promise<string> {
    return this.rpc<string>('sendrawtransaction', [txHex]);
  }

  async fetch(txId: string): Promise<FetchedTransaction> {
    const tx = checkRawTransaction(
      await this.rpc<unknown>('getrawtransaction', [txId, true]),
      txId,
    );
    return {
      txId: tx.txid,
      txHex: tx.hex,
      outs: tx.vout.map(out => ({
        // a colour carries a token count, not an amount of TPC
        value: out.token === 'TPC' ? toSatoshi(out.value) : out.value,
        address: (out.scriptPubKey.addresses || [])[0],
        script: Buffer.from(out.scriptPubKey.hex, 'hex'),
        token: out.token,
      })),
    };
  }

  /** Pays `value` satoshi to `address` and confirms it in a block. */
  async faucet(address: string, value: number): Promise<Unspent> {
    await this.ensureFunds(value);
    const txId = await this.rpc<string>('sendtoaddress', [
      address,
      toTpc(value),
    ]);
    await this.mine(1);
    const tx = await this.fetch(txId);
    const vout = tx.outs.findIndex(
      out => out.address === address && out.value === value,
    );
    if (vout < 0)
      throw new Error(`${txId} has no output of ${value} to ${address}`);
    return { txId, vout, value, address, script: tx.outs[vout].script };
  }

  /** Pays `value` satoshi to an arbitrary script and confirms it in a block. */
  async faucetComplex(output: Buffer, value: number): Promise<Unspent> {
    await this.ensureFunds(value);
    const tx = new tapyrus.Transaction();
    tx.addOutput(output, value);
    const funded = await this.rpc<{ hex: string }>('fundrawtransaction', [
      tx.toHex(),
    ]);
    const signed = await this.rpc<{ hex: string; complete: boolean }>(
      'signrawtransactionwithwallet',
      [funded.hex],
    );
    if (!signed.complete)
      throw new Error('the node could not sign the funding transaction');
    const txId = await this.broadcast(signed.hex);
    await this.mine(1);
    const confirmed = await this.fetch(txId);
    // fundrawtransaction inserts the change output at a random position
    const vout = confirmed.outs.findIndex(out => out.script.equals(output));
    if (vout < 0)
      throw new Error(`${txId} has no output paying to the given script`);
    return { txId, vout, value, script: output };
  }

  async verify(txo: {
    txId: string;
    vout: number;
    address?: string;
    value?: number;
  }): Promise<void> {
    const tx = await this.fetch(txo.txId);
    const actual = tx.outs[txo.vout];
    if (txo.address) assert.strictEqual(actual.address, txo.address);
    if (txo.value) assert.strictEqual(actual.value, txo.value);
  }

  /** A P2PKH address nobody holds the key for. */
  randomAddress(): string {
    const { address } = tapyrus.payments.p2pkh({
      hash: rng(20),
      network: NETWORK,
    });
    return address!;
  }

  /** Mines until the node's wallet can pay `value` satoshi plus a fee. */
  private async ensureFunds(value: number): Promise<void> {
    const needed = (value + 1e6) / 1e8;
    for (let mined = 0; ; mined++) {
      const balance = await this.rpc<number>('getbalance');
      if (balance >= needed) return;
      if (mined >= MAX_FUNDING_BLOCKS) {
        throw new Error(
          `The wallet balance is ${balance} after mining ${mined} blocks, ` +
            `short of the ${needed} needed. Blocks may be paying an address ` +
            'the node wallet does not hold, or the wallet may be disabled.',
        );
      }
      await this.mine(1);
    }
  }

  private async minerAddress(): Promise<string> {
    if (this.minerAddressCache === undefined) {
      this.minerAddressCache = await this.rpc<string>('getnewaddress');
    }
    return this.minerAddressCache;
  }
}

export const regtestUtils = new RegtestUtils();
