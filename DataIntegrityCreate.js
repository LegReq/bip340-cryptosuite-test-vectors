/*
    Steps to create a signed verifiable credential in the *DataIntegrityProof*
    representation with an Ed25519 signature.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { base58btc } from 'multiformats/bases/base58';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';

// Use this object to set input file and output directory.
const dirsAndFiles = {
  outputDir: './output/bip340-rdfc-2025/',
  inputFile: './input/unsigned.json'
}

// Create output directory for the results
const baseDir = dirsAndFiles.outputDir;
let status = await mkdir(baseDir, {recursive: true});

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const keyPair = JSON.parse(
  await readFile(
    new URL('./input/keyPair.json', import.meta.url)
  )
);

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL(dirsAndFiles.inputFile, import.meta.url)
    )
  );

// Signed Document Creation Steps:

// Canonize the document
let cannon = await jsonld.canonize(document);
console.log('Canonized unsigned document:')
console.log(cannon);
await writeFile(baseDir + 'canonDocDataInt.txt', cannon);

// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log('Hash of canonized document in hex:')
console.log(bytesToHex(docHash));
await writeFile(baseDir + 'docHashDataInt.txt', bytesToHex(docHash));

// Set proof options per draft
let proofConfig = {};
proofConfig.type = 'DataIntegrityProof';
proofConfig.cryptosuite = 'bip340-rdfc-2025';
proofConfig.created = '2023-02-24T23:36:38Z';
// proofConfig.verificationMethod = 'https://vc.example/issuers/5678#' + keyPair.publicKeyMultibase;
proofConfig.verificationMethod = 'did:key:' + keyPair.publicKeyMultibase + '#' + keyPair.publicKeyMultibase;

proofConfig.proofPurpose = 'assertionMethod';
proofConfig['@context'] = document['@context'];
await writeFile(baseDir + 'proofConfigDataInt.json', JSON.stringify(proofConfig, null, 2));

// canonize the proof config
let proofCanon = await jsonld.canonize(proofConfig);
console.log('Proof Configuration Canonized:');
console.log(proofCanon);
await writeFile(baseDir + 'proofCanonDataInt.txt', proofCanon);

// Hash canonized proof config
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log('Hash of canonized proof in hex:')
console.log(bytesToHex(proofHash));
await writeFile(baseDir + 'proofHashDataInt.txt', bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash); 
await writeFile(baseDir + 'combinedHashDataInt.txt', bytesToHex(combinedHash));

// Addition to BIP340 suite. Ensure always sign 32 bytes.
let hashData = sha256(combinedHash);
await writeFile(baseDir + 'finalHashDataInt.txt', bytesToHex(hashData));

let randomAux = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
writeFile(baseDir + 'randomAuxHexDataInt.txt', randomAux);
// Sign
let privKey = base58btc.decode(keyPair.privateKeyMultibase);
privKey = privKey.slice(2, 34); // only want the first 2-34 bytes
console.log(`Secret key length ${privKey.length}, value in hex:`);
let signature = await schnorr.sign(hashData, privKey, randomAux)
// let signature = await ed.sign(combinedHash, privKey);
await writeFile(baseDir + 'sigHexDataInt.txt', bytesToHex(signature));
console.log('Computed Signature from private key:');
console.log(base58btc.encode(signature));
await writeFile(baseDir + 'sigBTC58DataInt.txt', base58btc.encode(signature));

// Verify (just to see we have a good private/public pair)
let pbk = base58btc.decode(keyPair.publicKeyMultibase);
// First two bytes are multi-format indicator. Third byte is the y value, not required for schnorr
pbk = pbk.slice(3, pbk.length); 
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
let result = await schnorr.verify(signature, hashData, pbk);
console.log(`Signature verified: ${result}`);

// Construct Signed Document
let signedDocument = Object.assign({}, document);
delete proofConfig['@context'];
signedDocument.proof = proofConfig;
signedDocument.proof.proofValue = base58btc.encode(signature);

console.log(JSON.stringify(signedDocument, null, 2));
let res = await writeFile(baseDir + 'signedDataInt.json', JSON.stringify(signedDocument, null, 2));

