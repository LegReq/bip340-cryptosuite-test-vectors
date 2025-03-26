/*
    Steps to verify a signed verifiable credential in the *DataIntegrityProof*
    representation with Ed25519 signatures. Run this after DataIntegrityCreate.js
    or modify to read in a signed file of your choice. Caveat: No error checking
    is performed.
*/
import { readFile } from 'fs/promises';
import { localLoader } from './documentLoader.js';
import jsonld from 'jsonld';
import { base58btc } from "multiformats/bases/base58";
import {ed25519 as ed} from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1';

const baseDir = "./output/bip340-rdfc-2025/";
// const baseDir = "./output/eddsa-rdfc-2022/employ/";
// 
jsonld.documentLoader = localLoader;

// Read signed input document from a file or just specify it right here.
const signedDocument = JSON.parse(
    await readFile(
      new URL(baseDir + 'signedDataInt.json', import.meta.url)
    )
  );

// Document without proof
let document = Object.assign({}, signedDocument);
delete document.proof;
console.log(document);

// Canonize the document
let cannon = await jsonld.canonize(document);
console.log("Canonized unsigned document:")
console.log(cannon);

// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));

// Set proof options per draft
let proofConfig = {};
proofConfig.type = signedDocument.proof.type;
proofConfig.cryptosuite = signedDocument.proof.cryptosuite;
proofConfig.created = signedDocument.proof.created;
proofConfig.verificationMethod = signedDocument.proof.verificationMethod;
proofConfig.proofPurpose = signedDocument.proof.proofPurpose;
proofConfig["@context"] = signedDocument["@context"];

// canonize the proof config
let proofCanon = await jsonld.canonize(proofConfig);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);

// Hash canonized proof config
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized proof in hex:")
console.log(bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash); 

let hashData = sha256(combinedHash);

// Get public key
let encodedPbk = signedDocument.proof.verificationMethod.split("#")[1];
let pbk = base58btc.decode(encodedPbk);
// First two bytes are multi-format indicator. Third byte is the y value, not required for schnorr
pbk = pbk.slice(3, pbk.length);
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);

// Verify
let signature = base58btc.decode(signedDocument.proof.proofValue);
let result = await schnorr.verify(signature, hashData, pbk);
console.log(`Signature verified: ${result}`);
