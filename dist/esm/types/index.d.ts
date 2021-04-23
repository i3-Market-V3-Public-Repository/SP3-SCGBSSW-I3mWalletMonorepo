/**
 * My module description. Please update with your module data.
 *
 * @remarks
 * This module runs perfectly in node.js and browsers
 *
 * @packageDocumentation
 */
export { SIGNING_ALG, createJwk, createPoO, signProof, createPoR, createBlockchainProof } from './createProofs';
export { account, poO, poR } from './proofInterfaces';
export { validatePoR, validatePoO, validatePoP, decryptCipherblock, validateCipherblock, decodePoo, decodePor } from './validateProofs';
export { sha } from './sha';
//# sourceMappingURL=index.d.ts.map