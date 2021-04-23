import generateSecret from 'jose/util/generate_secret'
import fromKeyLike, { KeyLike, JWK } from 'jose/jwk/from_key_like'
import CompactEncrypt from 'jose/jwe/compact/encrypt'
import calculateThumbprint from 'jose/jwk/thumbprint'
import parseJwk from 'jose/jwk/parse'
import CompactSign from 'jose/jws/compact/sign'
import crypto from 'crypto'
import { account, poO, poR } from './proofInterfaces'
import { decodePoo } from './validateProofs'

/**
 * Create Proof of Origin and sign with Provider private key
 */
const createPoO = async (privateKey: KeyLike, block: ArrayBufferLike | string, providerId: string, consumerId: string, exchangeId: number, blockId: number, jwk: JWK): Promise<any> => {
  const input: Uint8Array  = (typeof block === 'string') ? (new TextEncoder()).encode(block) : new Uint8Array(block)
  const key: KeyLike = await parseJwk(jwk)
  const cipherblock: string = await new CompactEncrypt(input)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .encrypt(key)

  const hashCipherblock: string = crypto
    .createHash('sha256')
    .update(cipherblock)
    .digest('hex')
  const hashBlock: string = crypto.createHash('sha256').update(input).digest('hex')
  const hashKey: string = crypto
    .createHash('sha256')
    .update(JSON.stringify(jwk), 'utf8')
    .digest('hex')

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
 */
const createJwk = async (): Promise<JWK> => {
  const key: KeyLike = await generateSecret('HS256')
  const jwk: JWK = await fromKeyLike(key)
  const thumbprint: string = await calculateThumbprint(jwk)
  jwk.kid = thumbprint
  jwk.alg = 'HS256'

  return jwk
}

/**
 * Sign a proof with private key
 */
const signProof = async (privateKey: KeyLike, proof: any): Promise<string> => {
  const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(proof))
  const jws: string = await new CompactSign(jwt)
    .setProtectedHeader({ alg: 'EdDSA' })
    .sign(privateKey)

  return jws
}

/**
 * Create Proof of Receipt and sign with Consumer private key
 */
const createPoR = async (privateKey: KeyLike, poO: string, providerId: string, consumerId: string, exchangeId: number): Promise<string> => {
  const hashPooDgst: string = crypto.createHash('sha256').update(poO).digest('hex')

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
