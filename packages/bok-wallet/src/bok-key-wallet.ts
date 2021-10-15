import crypto from 'crypto'

import { ethers } from 'ethers'
import { v4 as uuid } from 'uuid'
import * as u8a from 'uint8arrays'

import { KeyLike, Dialog, Store, KeyWallet } from '@i3-market/base-wallet'

import { BokWalletModel, Key } from './types'
import { BokWalletError } from './errors'

export class BokKeyWallet implements KeyWallet {
  constructor (protected dialog: Dialog, protected store: Store<BokWalletModel>) { }

  async import (privateKeyHex: string): Promise<Key> {
    const kid = uuid()
    const publicKeyHex = ethers.utils.computePublicKey(`0x${privateKeyHex}`).substring(2)

    const key: Key = {
      kid,
      type: 'Secp256k1',
      publicKeyHex,
      privateKeyHex
    }
    const keys = await this.store.get('keys')

    await this.store.set('keys', {
      ...keys,
      [kid]: key
    })

    return key
  }

  async createAccountKeyPair (): Promise<string> {
    const privateKeyHex = crypto.randomBytes(32).toString('hex')
    const key = await this.import(privateKeyHex)
    return key.kid
  }

  async getPublicKey (kid: string): Promise<KeyLike> {
    const keys = await this.store.get('keys')
    if (keys === undefined) {
      throw new BokWalletError('No keys initialized yet')
    }

    return ethers.utils.arrayify(`0x${keys[kid].publicKeyHex}`)
  }

  async signDigest (kid: string, messageDigest: Uint8Array): Promise<Uint8Array> {
    const keys = await this.store.get('keys')
    if (keys === undefined) {
      throw new BokWalletError('No keys initialized yet')
    }

    // Get signing key
    const key = `0x${keys[kid].privateKeyHex}`
    const signingKey = new ethers.utils.SigningKey(key)

    // Ask for user confirmation
    const confirmation = await this.dialog.confirmation({
      title: 'Sign?',
      message: `Are you sure you want to sign using key <code>${key}</code> the following hex data: \n<code>${ethers.utils.hexlify(messageDigest)}</code>`,
      // authenticated: false,
      acceptMsg: 'Sign',
      rejectMsg: 'Reject'
    })
    if (confirmation !== true) {
      throw new BokWalletError('Signature rejected by user')
    }

    // Sign
    const signature: ethers.Signature = signingKey.signDigest(messageDigest)
    const signatureHex = ethers.utils.joinSignature(signature)

    // Remove 0x
    const fixedSignature = u8a.fromString(signatureHex.substring(2), 'base16')

    return fixedSignature
  }

  async delete (kid: string): Promise<boolean> {
    await this.store.delete(`keys.${kid}`)
    return true
  }

  async wipe (): Promise<void> { }
}
