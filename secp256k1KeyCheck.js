/* Checking encoding of public keys for ECDSA
   Keys from RFC6979 and draft did:key document
   https://w3c-ccg.github.io/did-method-key/#p-384
*/

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes, bytesToHex, concatBytes } from '@noble/hashes/utils';
import { base58btc } from "multiformats/bases/base58";
import varint from 'varint';
import { mkdir, writeFile } from 'fs/promises';
import { sha256 } from '@noble/hashes/sha256';

// Create output directory for the results
const baseDir = "./output/KeyCheck/";
let status = await mkdir(baseDir, {recursive: true});

// Multicodec information from https://github.com/multiformats/multicodec/
/*
name        tag     code    status      description
p256-pub	key	    0x1200	draft	    P-256 public Key (compressed)
p384-pub	key	    0x1201	draft	    P-384 public Key (compressed)
p256-priv key	    0x1306	draft	    P-256 private key
p384-priv key	    0x1307	draft	    P-384 private key
*/

// const P256_PUB_PREFIX = 0x1200;
// const P384_PUB_PREFIX = 0x1201;
// const P256_PRIV_PREFIX = 0x1306;
// const P384_PRIV_PREFIX = 0x1307;

let privKey = secp256k1.utils.randomPrivateKey()
let secpPubKey = secp256k1.getPublicKey(privKey);

const SECP256K1_PUB_PREFIX = 0xe7
const SECP256K1_XONLY_PREFX = 0x2561;
const SECP256K1_PRIV_PREFIX = 0x1301;

let myBytes = new Uint8Array(varint.encode(SECP256K1_XONLY_PREFX));
console.log(`Multicodec leading bytes in hex for SECP XONLY pubkey: ${bytesToHex(myBytes)}`);
myBytes = new Uint8Array(varint.encode(SECP256K1_PUB_PREFIX));
console.log(`Multicodec leading bytes in hex for SECP pubkey: ${bytesToHex(myBytes)}`);

myBytes = new Uint8Array(varint.encode(SECP256K1_PRIV_PREFIX));
console.log(`Multicodec leading bytes in hex for secp256k1 private keys: ${bytesToHex(myBytes)}`);


// Example keys from BIP340

console.log("BIP340 key example:");
let privateKey = schnorr.utils.randomPrivateKey()
// let privateKey = hexToBytes("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
let publicKey = schnorr.getPublicKey(privateKey);
console.log(`BIP340 private key length: ${privateKey.length}`);
console.log('BIP340 private key hex:');
console.log(bytesToHex(privateKey));
let privPrefix = new Uint8Array(varint.encode(SECP256K1_PRIV_PREFIX)); // Need to use varint on the multicodecs code
let privEncoded = base58btc.encode(concatBytes(privPrefix, privateKey));
console.log('Private secp256k1 encoded multikey:');
console.log(privEncoded, '\n');
console.log(privKey.length)
console.log(`Secp256k1 Pubic key length ${publicKey.length}`);
console.log('Secp256k1 public key in hex:');
console.log(bytesToHex(publicKey));

let pubPrefix = new Uint8Array(varint.encode(SECP256K1_PUB_PREFIX)); // Need to use varint on the multicodecs code
let pubEncoded = base58btc.encode(concatBytes(pubPrefix, hexToBytes("02"), publicKey));
console.log('Public schnorr encoded multikey:');

console.log(pubEncoded, '\n'); // Should start with z6D characters

let secpPubEncoded = base58btc.encode(concatBytes(pubPrefix, secpPubKey));
console.log('Public secp256k1 encoded multikey:');

console.log(secpPubEncoded, '\n'); // Should start with z6D characters

let xonlyPubPrefix = new Uint8Array(varint.encode(SECP256K1_XONLY_PREFX)); // Need to use varint on the multicodecs code

let xonlyPubEncoded = base58btc.encode(concatBytes(xonlyPubPrefix, publicKey));

console.log('Public xonly secp256k1 encoded multikey:');

console.log(xonlyPubEncoded, '\n'); // Should start with z66 characters

let secp256k1KeyPair = {
   "publicKeyMultibase": pubEncoded,
   "privateKeyMultibase": privEncoded
};
await writeFile(baseDir + 'secp256k1KeyPair.json', JSON.stringify(secp256k1KeyPair, null, 2));

// let privateKey384 = hexToBytes("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5");
// let publicKey384 = P384.getPublicKey(privateKey384);
// console.log(`P-384 private key length: ${privateKey384.length}`);
// console.log(bytesToHex(privateKey384));
// let priv384Prefix = new Uint8Array(varint.encode(P384_PRIV_PREFIX)); // Need to use varint on the multicodecs code
// let priv384Encoded = base58btc.encode(concatBytes(priv384Prefix, privateKey384));
// console.log('Private P-384 encoded multikey:');
// console.log(priv384Encoded, '\n'); // Should start with z2f characters

// console.log(`P-384 Pubic key length ${publicKey384.length}`);
// console.log('P-384 public key in hex:');
// console.log(bytesToHex(publicKey384));
// let p384Prefix = new Uint8Array(varint.encode(P384_PUB_PREFIX)); // Need to use varint on the multicodecs code
// let pub384Encoded = base58btc.encode(concatBytes(p384Prefix, publicKey384));
// console.log('P-384 encoded multikey:');
// console.log(pub384Encoded, '\n'); // Should start with z82

// let p384KeyPair = {
//    "publicKeyMultibase": pub384Encoded,
//    "privateKeyMultibase": priv384Encoded
// };
// await writeFile(baseDir + 'p384KeyPair.json', JSON.stringify(p384KeyPair, null, 2));

// From example 1 ECDSA-2019 P-384 public key
// "zsJV1eTDACogBS8FMj5vXSa51g1CY1y88DR2DGDwTsMTotTGELVH1XTEsFP8ok9q22ssAaqHN5fMgm1kweTABZZNRSc"
// This does not appear to be a valid P-384 key...
// Try: did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9
// let ex384multi = "z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9";
// let ex384bytes = base58btc.decode(ex384multi);
// console.log("DID:key example P384 key in hex bytes:");
// console.log(bytesToHex(ex384bytes));
// console.log(`Length of example P-384 key without prefix: ${ex384bytes.length-2}`);


// console.log(secpPubKey.SECP256K1_XONLY_PREFX)


// let privateKey2 = hexToBytes("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
let publicKey2 = schnorr.getPublicKey(privateKey);
// console.log(`BIP340 private key length: ${privateKey.length}`);
console.log('Are private keys equal');
console.log(bytesToHex(publicKey2) == bytesToHex(publicKey));



// console.log(secp256k1)


let testPrivKey = secp256k1.utils.randomPrivateKey()
let testSecpPubKey = secp256k1.getPublicKey(testPrivKey);
if (testSecpPubKey[0] == 3) {

   console.log("TESTING Flipping Bits")
   let msg = sha256("1234")
   console.log(bytesToHex(testSecpPubKey))
   
   let sig = schnorr.sign(bytesToHex(msg), testPrivKey)
   console.log(bytesToHex(sig))

   let schnorrPubKey = testSecpPubKey.subarray(1)
   // evenPubKey[0] = 2

   let res = schnorr.verify(bytesToHex(sig),bytesToHex(msg),schnorrPubKey)
   console.log(res)
} else {
   console.log("TESTING Even Key")
   let msg = sha256("1234")
   console.log(bytesToHex(testSecpPubKey))
   
   let sig = schnorr.sign(bytesToHex(msg), testPrivKey)
   console.log(bytesToHex(sig))

   let schnorrPubKey = testSecpPubKey.subarray(1)
   // evenPubKey[0] = 2
   console.log(schnorrPubKey)

   let res = schnorr.verify(bytesToHex(sig),bytesToHex(msg),schnorrPubKey)
   console.log(res)
}

