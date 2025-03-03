# Test Vector Creation and Validation for Multiple Verifiable Credential Proofs

> Adapted with gratitude from Greg Bernstein's eddsa test suite respository - https://github.com/Wind4Greg/EdDSA-Test-Vectors.

## BIP340-2025 Suite Test Vector Creation and Validation

For the [BIP340 Cryptosuite v2025](https://dcdpr.github.io/data-integrity-schnorr-secp256k1/) draft there are currently the following 
"Proof Representations" that need test vectors:

1. bip340-rdfc-2025 (type: "DataIntegrityProof", cryptosuite: "bip340-rdfc-2025")
2. bip340-jcs-2025 (type: "DataIntegrityProof", cryptosuite: "bip340-jcs-2025")

We have create corresponding pairs of creation/verification examples to create test vectors
that illustrate the procedures from the draft step by step using only the basic primitives
of: canonicalization, hashing, signatures, and multi-format decoding.

The unsigned document input to all the signing (creation) examples comes from the file
`input/unsigned.json` or can be put in line with the example code. Generated signed
credentials are put in the `output` directory which are then used in the verification
examples.


### Example Code

All example code uses `console.log` to produce output and write files to the `output` to generate the intermediate steps to show in test vectors.

1. [DataIntegrityCreate.js](DataIntegrityCreate.js) and [DataIntegrityVerify.js](DataIntegrityVerify.js) for the type: "DataIntegrityProof", cryptosuite: "bip340-rdfc-2025" case.
2. [JCSDataIntegrityCreate.js](JCSDataIntegrityCreate.js) and [JCSDataIntegrityVerify.js](JCSDataIntegrityVerify.js) for the type: "DataIntegrityProof", cryptosuite: "bip340-jcs-2025".


## Libraries Used

See the `package.json` file for the most up to date list. Currently we use `@noble/curves/secp256k1` for signatures, 
`@noble/hashes` for hashes, `canonicalize` for JSON Canonicalization Scheme (JCS), `jsonld` for JSON-LD based canonicalization, `multiformats` for multi-format decoding, and `varint` to help with multicodec encoding. More information on each of these packages can be obtained via [NPM](https://www.npmjs.com/).

No higher level signing libraries were used since our aim is to generate vendor independent test vectors for the specification.

## JSON-LD Usage

For the examples that utilize JSON-LD we have set up a "local document loader" and  local *contexts* so this code does not need to request resources from the net.

## How to Use

All examples are based on JavaScript and Node.js with package management via NPM. I have tried to limit the tools and techniques used to what I used to cover in a first course on [Web Programming](https://www.grotto-networking.com/WebsiteDevelopment/WebDev.html). This code is suitable for generating test vectors and understanding the procedures in the draft specification and not intended for any other purpose.


