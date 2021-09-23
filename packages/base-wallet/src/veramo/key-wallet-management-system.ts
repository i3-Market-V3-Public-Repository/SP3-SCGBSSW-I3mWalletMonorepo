import { TKeyType, IKey } from '@veramo/core'
import { AbstractKeyManagementSystem } from '@veramo/key-manager'
import { ethers } from 'ethers'
import * as u8a from 'uint8arrays'
import Debug from 'debug'

import { KeyWallet } from '../keywallet'

const debug = Debug('base-wallet:KMS')

export default class KeyWalletManagementSystem extends AbstractKeyManagementSystem {
  constructor (protected keyWallet: KeyWallet) {
    super()
  }

  async createKey (args: { type: TKeyType, meta?: any }): Promise<Omit<IKey, 'kms'>> {
    const type = args.type
    // TODO: Add type to createAccountKeyPair function
    const kid = await this.keyWallet.createAccountKeyPair()
    debug('Import', args, kid)

    const publicKey = await this.keyWallet.getPublicKey(kid)
    if (!(publicKey instanceof Uint8Array)) {
      // TODO: convert from string
      throw Error('Only Uint8Array supported yet')
    }

    return {
      kid,
      type,
      publicKeyHex: ethers.utils.hexlify(publicKey).substr(2) // TODO: Remove 0x from the string
    }
  }

  async deleteKey (args: { kid: string }): Promise<boolean> {
    await this.keyWallet.delete(args.kid)
    debug('Delete', args)
    return true
  }

  async encryptJWE (args: { key: IKey, to: Omit<IKey, 'kms'>, data: string }): Promise<string> {
    throw new Error('[encryptJWE] Method not implemented.')
  }

  async decryptJWE (args: { key: IKey, data: string }): Promise<string> {
    throw new Error('[decryptJWE] Method not implemented.')
  }

  async signJWT (args: { key: IKey, data: string | Uint8Array }): Promise<string> {
    let message: Uint8Array
    const { key, data } = args

    if (typeof data === 'string') {
      message = u8a.fromString(data, 'utf-8')
    } else {
      message = data
    }

    const messageDigest = ethers.utils.sha256(message)
    const messageDigestBytes = ethers.utils.arrayify(messageDigest)
    const signature = await this.keyWallet.signDigest(key.kid, messageDigestBytes)
    const signatureBase64url = u8a.toString(signature, 'base64url')

    return signatureBase64url
  }

  async signEthTX (args: { key: IKey, transaction: object }): Promise<string> {
    const signature = await this.keyWallet.signDigest(args.key as any, args.transaction as Uint8Array)
    return signature.toString() // TODO: Convert properly
  }
}
