const bulletproof = require('bulletproof-js');
const fs = require('fs');

const CompressedProofs = bulletproof.CompressedProofs;

const json = fs.readFileSync('proof.json');
const prf = CompressedProofs.fromJsonString(json);
console.log(prf.verify(0n, 64n) ? 'Valid proof' : 'Invalid Proof');