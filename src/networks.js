'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.NetworkId = exports.dev = exports.prod = void 0;
exports.prod = {
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
exports.dev = {
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
var NetworkId;
(function(NetworkId) {
  NetworkId[(NetworkId['TAPYRUS_API'] = 15215628)] = 'TAPYRUS_API';
  NetworkId[(NetworkId['TESTNET'] = 1939510133)] = 'TESTNET';
})(NetworkId || (exports.NetworkId = NetworkId = {}));
