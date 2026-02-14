'use strict';
var __awaiter =
  (this && this.__awaiter) ||
  function(thisArg, _arguments, P, generator) {
    function adopt(value) {
      return value instanceof P
        ? value
        : new P(function(resolve) {
            resolve(value);
          });
    }
    return new (P || (P = Promise))(function(resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator['throw'](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done
          ? resolve(result.value)
          : adopt(result.value).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.Metadata = void 0;
const crypto = require('./crypto');
const payments = require('./payments');
const canonicalize = require('canonicalize');
const ecc = require('tiny-secp256k1');
const MAX_NAME_LENGTH = 64;
const MAX_SYMBOL_LENGTH = 12;
const MAX_DECIMALS = 18;
const MAX_DESCRIPTION_LENGTH = 256;
const MAX_DATA_URI_SIZE = 32768;
const COLOR_ID_REISSUABLE = 0xc1;
const COLOR_ID_NON_REISSUABLE = 0xc2;
const COLOR_ID_NFT = 0xc3;
const VALID_TOKEN_TYPES = ['reissuable', 'non_reissuable', 'nft'];
const COLOR_ID_TYPE_MAP = {
  [COLOR_ID_REISSUABLE]: 'reissuable',
  [COLOR_ID_NON_REISSUABLE]: 'non_reissuable',
  [COLOR_ID_NFT]: 'nft',
};
function isHttpsUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:';
  } catch (_a) {
    return false;
  }
}
function isDataUri(value) {
  return value.startsWith('data:');
}
function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function getDataUriSize(value) {
  const base64Match = value.match(/^data:[^,]+;base64,(.*)$/);
  if (base64Match) {
    return Buffer.from(base64Match[1], 'base64').length;
  }
  const plainMatch = value.match(/^data:[^,]*,(.*)$/);
  if (plainMatch) {
    return Buffer.from(decodeURIComponent(plainMatch[1])).length;
  }
  return value.length;
}
const DEFAULT_REGISTRY_URL =
  'https://chaintope.github.io/tapyrus-token-registry';
class Metadata {
  static fromJSON(json) {
    const fields = JSON.parse(json);
    return new Metadata(fields);
  }
  static fetch(colorId_1, networkId_1) {
    return __awaiter(this, arguments, void 0, function*(
      colorId,
      networkId,
      baseUrl = DEFAULT_REGISTRY_URL,
    ) {
      const url = `${baseUrl}/tokens/${networkId}/${colorId}.json`;
      const response = yield fetch(url);
      if (!response.ok) {
        throw new Error(
          `Failed to fetch metadata: ${response.status} ${response.statusText}`,
        );
      }
      const json = yield response.text();
      const fields = JSON.parse(json);
      if (!fields.tokenType) {
        const prefix = parseInt(colorId.substring(0, 2), 16);
        const tokenType = COLOR_ID_TYPE_MAP[prefix];
        if (!tokenType) {
          throw new Error(
            `Unknown color id prefix: ${colorId.substring(0, 2)}`,
          );
        }
        fields.tokenType = tokenType;
      }
      return new Metadata(fields);
    });
  }
  static validate(fields) {
    // version
    if (!fields.version) {
      throw new Error('version is required');
    }
    if (fields.version !== '1.0') {
      throw new Error('version must be 1.0');
    }
    // tokenType
    if (!fields.tokenType) {
      throw new Error('tokenType is required');
    }
    if (!VALID_TOKEN_TYPES.includes(fields.tokenType)) {
      throw new Error('tokenType must be reissuable, non_reissuable, or nft');
    }
    // name
    if (!fields.name) {
      throw new Error('name is required');
    }
    if (fields.name.length > MAX_NAME_LENGTH) {
      throw new Error('name must be 64 characters or less');
    }
    // symbol
    if (!fields.symbol) {
      throw new Error('symbol is required');
    }
    if (fields.symbol.length > MAX_SYMBOL_LENGTH) {
      throw new Error('symbol must be 12 characters or less');
    }
    // decimals
    if (fields.decimals !== undefined) {
      if (fields.decimals < 0 || fields.decimals > MAX_DECIMALS) {
        throw new Error('decimals must be between 0 and 18');
      }
    }
    // description
    if (fields.description !== undefined) {
      if (fields.description.length > MAX_DESCRIPTION_LENGTH) {
        throw new Error('description must be 256 characters or less');
      }
    }
    // website
    if (fields.website !== undefined) {
      if (!isHttpsUrl(fields.website)) {
        throw new Error('website must be an HTTPS URL');
      }
    }
    // terms
    if (fields.terms !== undefined) {
      if (!isHttpsUrl(fields.terms)) {
        throw new Error('terms must be an HTTPS URL');
      }
    }
    // external_url
    if (fields.external_url !== undefined) {
      if (!isHttpsUrl(fields.external_url)) {
        throw new Error('external_url must be an HTTPS URL');
      }
    }
    // icon
    if (fields.icon !== undefined) {
      if (!isHttpsUrl(fields.icon) && !isDataUri(fields.icon)) {
        throw new Error('icon must be an HTTPS URL or Data URI');
      }
      if (
        isDataUri(fields.icon) &&
        getDataUriSize(fields.icon) > MAX_DATA_URI_SIZE
      ) {
        throw new Error('icon must be an HTTPS URL or Data URI');
      }
    }
    // image
    if (fields.image !== undefined) {
      if (!isHttpsUrl(fields.image) && !isDataUri(fields.image)) {
        throw new Error('image must be an HTTPS URL or Data URI');
      }
      if (
        isDataUri(fields.image) &&
        getDataUriSize(fields.image) > MAX_DATA_URI_SIZE
      ) {
        throw new Error('image must be an HTTPS URL or Data URI');
      }
    }
    // animation_url
    if (fields.animation_url !== undefined) {
      if (
        !isHttpsUrl(fields.animation_url) &&
        !isDataUri(fields.animation_url)
      ) {
        throw new Error('animation_url must be an HTTPS URL or Data URI');
      }
      if (
        isDataUri(fields.animation_url) &&
        getDataUriSize(fields.animation_url) > MAX_DATA_URI_SIZE
      ) {
        throw new Error('animation_url must be an HTTPS URL or Data URI');
      }
    }
    // issuer
    if (fields.issuer !== undefined) {
      if (fields.issuer.url !== undefined) {
        if (!isHttpsUrl(fields.issuer.url)) {
          throw new Error('issuer.url must be an HTTPS URL');
        }
      }
      if (fields.issuer.email !== undefined) {
        if (!isValidEmail(fields.issuer.email)) {
          throw new Error('issuer.email must be a valid email address');
        }
      }
    }
    // NFT-only fields validation
    if (fields.tokenType !== 'nft') {
      if (fields.image !== undefined) {
        throw new Error('image is only allowed for nft token type');
      }
      if (fields.animation_url !== undefined) {
        throw new Error('animation_url is only allowed for nft token type');
      }
      if (fields.external_url !== undefined) {
        throw new Error('external_url is only allowed for nft token type');
      }
      if (fields.attributes !== undefined) {
        throw new Error('attributes is only allowed for nft token type');
      }
    }
  }
  constructor(fields) {
    Metadata.validate(fields);
    this.version = fields.version;
    this.name = fields.name;
    this.symbol = fields.symbol;
    this.tokenType = fields.tokenType;
    if (fields.decimals !== undefined && fields.decimals !== 0) {
      this.decimals = fields.decimals;
    }
    if (fields.description) {
      this.description = fields.description;
    }
    if (fields.icon) {
      this.icon = fields.icon;
    }
    if (fields.website) {
      this.website = fields.website;
    }
    if (fields.issuer) {
      this.issuer = fields.issuer;
    }
    if (fields.terms) {
      this.terms = fields.terms;
    }
    if (fields.properties && Object.keys(fields.properties).length > 0) {
      this.properties = fields.properties;
    }
    if (fields.image) {
      this.image = fields.image;
    }
    if (fields.animation_url) {
      this.animation_url = fields.animation_url;
    }
    if (fields.external_url) {
      this.external_url = fields.external_url;
    }
    if (fields.attributes && fields.attributes.length > 0) {
      this.attributes = fields.attributes;
    }
  }
  toCanonical() {
    const obj = {};
    if (this.animation_url !== undefined) {
      obj.animation_url = this.animation_url;
    }
    if (this.attributes !== undefined) {
      obj.attributes = this.attributes;
    }
    if (this.decimals !== undefined) {
      obj.decimals = this.decimals;
    }
    if (this.description !== undefined) {
      obj.description = this.description;
    }
    if (this.external_url !== undefined) {
      obj.external_url = this.external_url;
    }
    if (this.icon !== undefined) {
      obj.icon = this.icon;
    }
    if (this.image !== undefined) {
      obj.image = this.image;
    }
    if (this.issuer !== undefined) {
      obj.issuer = this.issuer;
    }
    obj.name = this.name;
    if (this.properties !== undefined) {
      obj.properties = this.properties;
    }
    obj.symbol = this.symbol;
    if (this.terms !== undefined) {
      obj.terms = this.terms;
    }
    obj.version = this.version;
    if (this.website !== undefined) {
      obj.website = this.website;
    }
    return canonicalize(obj);
  }
  digest() {
    const canonical = this.toCanonical();
    return crypto.sha256(Buffer.from(canonical, 'utf8'));
  }
  toObject() {
    const obj = {
      version: this.version,
      name: this.name,
      symbol: this.symbol,
      tokenType: this.tokenType,
    };
    if (this.decimals !== undefined) {
      obj.decimals = this.decimals;
    }
    if (this.description !== undefined) {
      obj.description = this.description;
    }
    if (this.icon !== undefined) {
      obj.icon = this.icon;
    }
    if (this.website !== undefined) {
      obj.website = this.website;
    }
    if (this.issuer !== undefined) {
      obj.issuer = this.issuer;
    }
    if (this.terms !== undefined) {
      obj.terms = this.terms;
    }
    if (this.properties !== undefined) {
      obj.properties = this.properties;
    }
    if (this.image !== undefined) {
      obj.image = this.image;
    }
    if (this.animation_url !== undefined) {
      obj.animation_url = this.animation_url;
    }
    if (this.external_url !== undefined) {
      obj.external_url = this.external_url;
    }
    if (this.attributes !== undefined) {
      obj.attributes = this.attributes;
    }
    return obj;
  }
  commitment(publicKey) {
    if (publicKey.length !== 33) {
      throw new Error('publicKey must be 33 bytes (compressed)');
    }
    const h = this.digest();
    return crypto.sha256(Buffer.concat([publicKey, h]));
  }
  p2cPublicKey(publicKey) {
    const c = this.commitment(publicKey);
    const result = ecc.pointAddScalar(publicKey, c);
    if (!result) {
      throw new Error('Failed to derive P2C public key');
    }
    return Buffer.from(result);
  }
  p2cAddress(publicKey, network) {
    const p2cPubKey = this.p2cPublicKey(publicKey);
    const { address } = payments.p2pkh({ pubkey: p2cPubKey, network });
    return address;
  }
  deriveColorId(publicKey, outPoint) {
    switch (this.tokenType) {
      case 'reissuable': {
        if (!publicKey) {
          throw new Error('publicKey is required for reissuable token');
        }
        const p2cPubKey = this.p2cPublicKey(publicKey);
        const pubKeyHash = crypto.hash160(p2cPubKey);
        // P2PKH script: OP_DUP OP_HASH160 <20bytes> OP_EQUALVERIFY OP_CHECKSIG
        const script = Buffer.alloc(25);
        script[0] = 0x76; // OP_DUP
        script[1] = 0xa9; // OP_HASH160
        script[2] = 0x14; // 20 bytes
        pubKeyHash.copy(script, 3);
        script[23] = 0x88; // OP_EQUALVERIFY
        script[24] = 0xac; // OP_CHECKSIG
        const scriptHash = crypto.sha256(script);
        const colorId = Buffer.alloc(33);
        colorId[0] = COLOR_ID_REISSUABLE;
        scriptHash.copy(colorId, 1);
        return colorId;
      }
      case 'non_reissuable': {
        if (!outPoint) {
          throw new Error('outPoint is required for non_reissuable token');
        }
        const outPointPayload = Buffer.alloc(36);
        outPoint.txid.copy(outPointPayload, 0);
        outPointPayload.writeUInt32LE(outPoint.index, 32);
        const outPointHash = crypto.sha256(outPointPayload);
        const colorId = Buffer.alloc(33);
        colorId[0] = COLOR_ID_NON_REISSUABLE;
        outPointHash.copy(colorId, 1);
        return colorId;
      }
      case 'nft': {
        if (!outPoint) {
          throw new Error('outPoint is required for nft token');
        }
        const outPointPayload = Buffer.alloc(36);
        outPoint.txid.copy(outPointPayload, 0);
        outPointPayload.writeUInt32LE(outPoint.index, 32);
        const outPointHash = crypto.sha256(outPointPayload);
        const colorId = Buffer.alloc(33);
        colorId[0] = COLOR_ID_NFT;
        outPointHash.copy(colorId, 1);
        return colorId;
      }
      default:
        throw new Error('Invalid token type');
    }
  }
}
exports.Metadata = Metadata;
