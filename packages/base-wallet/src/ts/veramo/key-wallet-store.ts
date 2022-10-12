import { IKey } from '@veramo/core'
import { AbstractKeyStore } from '@veramo/key-manager'
import { utils } from 'ethers'
import Debug from 'debug'

import { KeyWallet } from '../keywallet'

const debug = Debug('base-wallet:KeyWalletStore')

export default class KeyWalletStore extends AbstractKeyStore {
  constructor (protected keyWallet: KeyWallet) {
    super()
  }

  async import (args: IKey): Promise<boolean> {
    debug('Import key. Doing nothing')
    return true
  }

  async get (args: { kid: string }): Promise<IKey> {
    // TODO: Add type to createAccountKeyPair function
    const kid = args.kid
    debug('Get key', args, kid)

    const publicKey = await this.keyWallet.getPublicKey(kid)
    if (!(publicKey instanceof Uint8Array)) {
      throw Error('Only Uint8Array supported yet')
    }

    // TODO: Set type properly
    return {
      kid,
      type: 'Secp256k1',
      kms: 'keyWallet',
      publicKeyHex: utils.hexlify(publicKey).substr(2)
    }
  }

  async delete (args: { kid: string }): Promise<boolean> {
    return true
  }
}
