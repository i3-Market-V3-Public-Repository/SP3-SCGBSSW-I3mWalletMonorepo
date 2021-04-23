import { KeyLike, JWK } from 'jose/jwk/from_key_like'
import parseJwk from 'jose/jwk/parse'
import compactDecrypt from 'jose/jwe/compact/decrypt'
import compactVerify from 'jose/jws/compact/verify'
import sha from './sha'
import { poO, poR } from './proofInterfaces'

// TODO decide a fixed delay for the protocol
const IAT_DELAY = 5000

/**
 * Validate Proof or Request using the Provider Public Key
 */
const validatePoR = async (publicKey: KeyLike, poR: string, poO: string): Promise<boolean> => {
  const poRpayload: poR = await decodePor(publicKey, poR)
  const hashPooDgst: string = await sha(poO)

  if (hashPooDgst !== poRpayload.exchange.poo_dgst) {
    throw new Error('the hashed proof of origin received does not correspond to the poo_dgst parameter in the proof of origin')
  } else if (Date.now() - poRpayload.iat > IAT_DELAY) {
    throw new Error('timestamp error')
  } else {
    return true
  }
}

/**
 * Decode Proof of Reception with Consumer public key
 */
const decodePor = async (publicKey: KeyLike, poR: string): Promise<poR> => {
  const { payload } = await compactVerify(poR, publicKey).catch((e) => {
    throw new Error(`PoR: ${String(e)}`)
  })
  const decodedPoOPayload: poR = JSON.parse(new TextDecoder().decode(payload).toString())
  return decodedPoOPayload
}

/**
 * Validate Proof or Origin using the Consumer Public Key
 */
const validatePoO = async (publicKey: KeyLike, poO: string, cipherblock: string): Promise<boolean> => {
  const poOpayload: poO = await decodePoo(publicKey, poO)
  const hashedCipherBlock: string = await sha(cipherblock)

  if (poOpayload.exchange.cipherblock_dgst !== hashedCipherBlock) {
    throw new Error('the cipherblock_dgst parameter in the proof of origin does not correspond to hash of the cipherblock received by the provider')
  } else if (Date.now() - poOpayload.iat > IAT_DELAY) {
    throw new Error('timestamp error')
  } else {
    return true
  }
}

/**
 * Decode Proof of Origin with Provider public key
 */
const decodePoo = async (publicKey: KeyLike, poO: string): Promise<poO> => {
  const { payload } = await compactVerify(poO, publicKey).catch((e) => {
    throw new Error('PoO ' + String(e))
  })
  const decodedPoOPayload: poO = JSON.parse(new TextDecoder().decode(payload).toString())
  return decodedPoOPayload
}

/**
 * Validate Proof of Publication using the Backplain Public Key
 */
const validatePoP = async (publicKeyBackplain: KeyLike, publicKeyProvider: KeyLike, poP: string, jwk: JWK, poO: string): Promise<boolean> => {
  await compactVerify(poP, publicKeyBackplain).catch((e) => {
    throw new Error('PoP ' + String(e))
  })

  const poOPayload: poO = await decodePoo(publicKeyProvider, poO)
  const hashedJwk: string = await sha(JSON.stringify(jwk))

  if (poOPayload.exchange.key_commitment === hashedJwk) {
    return true
  } else {
    throw new Error('hashed key not correspond to poO key_commitment parameter')
  }
}

/**
 * Decrypt the cipherblock received
 */
const decryptCipherblock = async (chiperblock: string, jwk: JWK): Promise<string> => {
  const decoder = new TextDecoder()
  const key: KeyLike = await parseJwk(jwk, 'A256GCM') // TODO: ENC_ALG

  const { plaintext } = await compactDecrypt(chiperblock, key)
  return decoder.decode(plaintext)
}

/**
 * Validate the cipherblock
 */
const validateCipherblock = async (publicKey: KeyLike, chiperblock: string, jwk: JWK, poO: poO): Promise<boolean> => {
  const decodedCipherBlock = await decryptCipherblock(chiperblock, jwk)
  const hashedDecodedCipherBlock: string = await sha(decodedCipherBlock)

  if (hashedDecodedCipherBlock === poO.exchange.block_commitment) {
    // TODO check also block_description
    return true
  } else {
    throw new Error('hashed CipherBlock not correspond to block_commitment parameter included in the proof of origin')
  }
}

export { validatePoR, validatePoO, validatePoP, decryptCipherblock, validateCipherblock, decodePoo, decodePor }
