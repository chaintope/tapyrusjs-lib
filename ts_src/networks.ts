// https://en.bitcoin.it/wiki/List_of_address_prefixes
// Dogecoin BIP32 is a proposed standard: https://bitcointalk.org/index.php?topic=409731
export interface Network {
  messagePrefix: string;
  bip32: Bip32;
  pubKeyHash: number;
  scriptHash: number;
  coloredPubKeyHash: number;
  coloredScriptHash: number;
  wif: number;
}

interface Bip32 {
  public: number;
  private: number;
}

export const prod: Network = {
  messagePrefix: '\x18Tapyrus Signed Message:\n',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  coloredPubKeyHash: 0x01,
  coloredScriptHash: 0x06,
  wif: 0x80,
};
export const dev: Network = {
  messagePrefix: '\x18Tapyrus Signed Message:\n',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  coloredPubKeyHash: 0x70,
  coloredScriptHash: 0xc5,
  wif: 0xef,
};

export enum NetworkId {
  TAPYRUS_API = 15215628,
  TESTNET = 1939510133,
}
