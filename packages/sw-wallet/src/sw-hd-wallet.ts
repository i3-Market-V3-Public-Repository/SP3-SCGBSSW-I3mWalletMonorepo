import crypto from 'crypto'

import { ethers } from 'ethers'
import { HDNode, defaultPath } from '@ethersproject/hdnode'
import * as u8a from 'uint8arrays'

import { KeyLike, Dialog, Store, KeyWallet } from '@i3-market/base-wallet'
import { SwWalletError } from './errors'
import { SwWalletModel, HDData } from './types'

export class SwHdKeyWallet implements KeyWallet {
  _hdNode?: HDNode
  _hdData?: HDData

  constructor (protected dialog: Dialog, protected store: Store<SwWalletModel>) { }

  protected get hdData (): HDData {
    if (this._hdData === undefined) {
      throw new SwWalletError('Hierarchical Deterministic data is undefined')
    }
    return this._hdData
  }

  protected get hdNode (): HDNode {
    if (this._hdNode === undefined) {
      throw new SwWalletError('Hierarchical Deterministic node is undefined')
    }
    return this._hdNode
  }

  protected async updateHdData (): Promise<void> {
    await this.store.set('hdData', this.hdData)
  }

  async initialize (): Promise<void> {
    let hdData = await this.store.get('hdData')

    if (hdData === undefined) {
      let mnemonic = await this.dialog.text({
        title: 'Initializing wallet',
        message: 'Use your backed BIP39 mnemmonic words (12 or 24 words) or escape for generating new ones'
      })

      // TODO: Throw execption if invalid mnemonic
      if (mnemonic === undefined || mnemonic.trim() === '') {
        const entropy = crypto.randomBytes(32)
        mnemonic = ethers.utils.entropyToMnemonic(entropy)
      } else if (!ethers.utils.isValidMnemonic(mnemonic)) {
        throw new SwWalletError('Not valid mnemonic')
      }

      const confirmation = await this.dialog.confirmation({
        title: 'Init wallet?',
        message: `A new wallet is going to be created. Please note down to a secure place the following list of BIP39 words. It can be used to restore your wallet in the future.\n<input value="${mnemonic}" disabled></input>\n\n Do you want to continue?`
      })
      if (confirmation !== true) {
        throw new SwWalletError('Initialization cancelled by the user')
      }

      hdData = { mnemonic, accounts: 0 }
      await this.store.set('hdData', hdData)
    }

    if (!ethers.utils.isValidMnemonic(hdData.mnemonic)) {
      throw new SwWalletError('Not valid mnemonic')
    }

    this._hdData = hdData
    const seed = ethers.utils.mnemonicToSeed(hdData.mnemonic)
    await this.initializeSeed(ethers.utils.arrayify(seed))
  }

  async initializeSeed (seed: Uint8Array): Promise<void> {
    this._hdNode = ethers.utils.HDNode.fromSeed(seed)

    /* TODO: Not sure if ethers implement BIP44 Account Discovery, but just in case let us add all the potentially discovered accounts */
    // let accounts = 0
    // for (let i = 0; i <= this.hdNode.depth; i++) {
    //   accounts++
    // }
    // await this.updateAccounts(accounts)
  }

  // TODO: IMPLEMENT METHODS!
  async createAccountKeyPair (): Promise<string> {
    const { hdNode, hdData } = this

    // TODO: Check how paths work on ethers
    let path = defaultPath
    if (hdNode.path !== null) {
      path = hdNode.path
    }

    const pathArr = path.split('/')
    hdData.accounts++
    pathArr[3] = `${hdData.accounts}'`
    const kid = pathArr.join('/')

    // Update accounts
    await this.updateHdData()

    return kid
  }

  async getPublicKey (path: string): Promise<KeyLike> {
    const { hdNode } = this
    const key = hdNode.derivePath(path)
    return ethers.utils.arrayify(key.publicKey)
  }

  async signDigest (path: string, messageDigest: Uint8Array): Promise<Uint8Array> {
    const { hdNode } = this

    // Get signing key
    const childHdNode = hdNode.derivePath(path)
    const key = childHdNode.privateKey
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
      throw new SwWalletError('Signature rejected by user')
    }

    // Sign
    const signature: ethers.Signature = signingKey.signDigest(messageDigest)
    const signatureHex = ethers.utils.joinSignature(signature)

    // Remove 0x
    const fixedSignature = u8a.fromString(signatureHex.substring(2), 'base16')

    return fixedSignature
  }

  async delete (id: string): Promise<boolean> {
    // Keys are not stored in any place
    return true
  }

  async wipe (): Promise<void> {
    // Perform delete
    delete this._hdNode
    await this.store.delete('hdData')

    // Reinitialize
    await this.initialize()
  }
}
