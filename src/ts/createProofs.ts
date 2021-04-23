import generateSecret from 'jose/util/generate_secret'
import fromKeyLike, { KeyLike, JWK } from 'jose/jwk/from_key_like'
import CompactEncrypt from 'jose/jwe/compact/encrypt'
import calculateThumbprint from 'jose/jwk/thumbprint'
import parseJwk from 'jose/jwk/parse'
import CompactSign from 'jose/jws/compact/sign'
import sha from './sha'
import { account, poO, poR } from './proofInterfaces'
import { decodePoo } from './validateProofs'

export const SIGNING_ALG = 'ES256'
export const ENC_ALG = 'AES-GCM'
export const ENC_ALG_KEY_LENGTH = 256

/**
 *
 * Create Proof of Origin and sign with Provider private key
 *
 * @param privateKey - private key of the signer/issuer
 * @param block - the blocks asdfsdfsd
 * @param providerId
 * @param consumerId
 * @param exchangeId
 * @param blockId
 * @param jwk
 * @returns
 */
const createPoO = async (privateKey: KeyLike, block: ArrayBufferLike | string, providerId: string, consumerId: string, exchangeId: number, blockId: number, jwk: JWK): Promise<{ cipherblock: string, poO: string }> => {
  const input: Uint8Array = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  const key: KeyLike = await parseJwk(jwk)
  const cipherblock: string = await new CompactEncrypt(input)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .encrypt(key)

  const hashCipherblock: string = await sha(cipherblock)
  const hashBlock: string = await sha(input)
  const hashKey: string = await sha(JSON.stringify(jwk))

  const proof: poO = {
    iss: providerId,
    sub: consumerId,
    iat: Date.now(),
    exchange: {
      id: exchangeId,
      orig: providerId,
      dest: consumerId,
      block_id: blockId,
      block_desc: 'description',
      hash_alg: 'sha256',
      cipherblock_dgst: hashCipherblock,
      block_commitment: hashBlock,
      key_commitment: hashKey
    }
  }

  const signedProof: string = await signProof(privateKey, proof)
  return { cipherblock: cipherblock, poO: signedProof }
}

/**
 * Create random (high entropy)\none time symmetric JWK secret
 *
 * @returns a promise that resolves to a JWK
 */
const createJwk = async (): Promise<JWK> => {
  let key: KeyLike
  if (IS_BROWSER) {
    key = await window.crypto.subtle.generateKey(
      {
        name: ENC_ALG,
        length: ENC_ALG_KEY_LENGTH
      },
      true,
      ['encrypt', 'decrypt']
    )
  } else {
    // TODO: get algo from ENC_ALG
    key = await generateSecret('A256GCM')
  }
  const jwk: JWK = await fromKeyLike(key)
  const thumbprint: string = await calculateThumbprint(jwk)
  jwk.kid = thumbprint
  jwk.alg = 'A256GCM'

  return jwk
}

/**
 * Sign a proof with private key
 */
const signProof = async (privateKey: KeyLike, proof: any): Promise<string> => {
  const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(proof))
  const jws: string = await new CompactSign(jwt)
    .setProtectedHeader({ alg: SIGNING_ALG })
    .sign(privateKey)

  return jws
}

/**
 * Create Proof of Receipt and sign with Consumer private key
 */
const createPoR = async (privateKey: KeyLike, poO: string, providerId: string, consumerId: string, exchangeId: number): Promise<string> => {
  const hashPooDgst: string = await sha(poO)

  const proof: poR = {
    iss: providerId,
    sub: consumerId,
    iat: Date.now(),
    exchange: {
      poo_dgst: hashPooDgst,
      hash_alg: 'sha256',
      exchangeId: exchangeId
    }
  }

  const signedProof: string = await signProof(privateKey, proof)
  return signedProof
}

/**
 *
 * Prepare block to be send to the Backplain API
 */
const createBlockchainProof = async (publicKey: KeyLike, poO: string, poR: string, jwk: JWK): Promise<account> => {
  const decodedPoO: poO = await decodePoo(publicKey, poO)

  const privateStorage = {
    availability: 'privateStorage',
    permissions: {
      view: [decodedPoO.exchange.orig, decodedPoO.exchange.dest]
    },
    type: 'dict',
    id: decodedPoO.exchange.id,
    content: { [decodedPoO.exchange.block_id]: { poO: poO, poR: poR } }
  }

  const blockchain = {
    availability: 'blockchain',
    type: 'jwk',
    content: { [jwk.kid!]: jwk } // eslint-disable-line
  }

  return { privateStorage, blockchain }
}

/*
//TODO send json to Auditable Accounting

let sendBlockToBackplainApi = async (block:account, backplainUrl:string) : Promise<string> => {

    const response = await post<{ id: number }>(
        backplainUrl,
        block
    );

    return response;
}

export async function post<T>(
    path: string,
    body: any,
    args: RequestInit = { method: "post", body: JSON.stringify(body) }
  ): Promise<HttpResponse<T>>  {
    return await http<T>(new Request(path, args));
};

*/

export { createJwk, createPoO, signProof, createPoR, createBlockchainProof }
