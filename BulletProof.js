const bulletproofs = require('bulletproof-js');
const EC = require('elliptic').ec;
const cryptoutils = require('bigint-crypto-utils');

const ProofFactory = bulletproofs.ProofFactory;
const ProofUtils = bulletproofs.ProofUtils;
const constants = bulletproofs.Constants;
const secp256k1 = constants.secp256k1;
const ec = new EC('secp256k1');

// Manually define the orthogonal generator H
const G = ec.g;
const H = G.mul(cryptoutils.randBetween(secp256k1.n));

// Random blinding factor
const x = cryptoutils.randBetween(secp256k1.n);

// Amount to which we commit
const a = 25003n;

// Lower and upper bound of range proof (this will be treated as exponents of 2)
const low = 0n;
const upper = 64n;

// Pedersen Commitment to our amount
const V = ProofUtils.getPedersenCommitment(a, x, secp256k1.n, H);

// Compute an uncompressed proof first. Note the last parameter will switch off asserts improving performance
const uncompr_proof = ProofFactory.computeBulletproof(a, x, V, G, H, low, upper, secp256k1.n, false);
// Compress proof using the inner product protocol (Again pass false to switch off asserts)
const compr_proof = uncompr_proof.compressProof(false);

// Proofs can be serialized and deserialized to and from JSON.
console.log(compr_proof.toJson(true));
// Verify a proof calling the verify function on the proof object (works on both uncompressed and compressed version)
console.log(compr_proof.verify(low, upper) ? 'Valid proof' : 'Invalid Proof');