import { Provider, TransactionRequest } from '@ethersproject/abstract-provider'
import { SigningKey } from '@ethersproject/signing-key'
import { Wallet } from '@ethersproject/wallet'
import { hexToBuf } from 'bigint-conversion'
import { DltSigner } from './Signer'

/**
 * A ledger signer using an ethers.io Wallet.
 */
export class EthersSigner implements DltSigner {
  signer: Wallet

  /**
   *
   * @param provider
   * @param privateKey the private key as an hexadecimal string ot Uint8Array
   */
  constructor (provider: Provider, privateKey: string | Uint8Array) {
    const privKey = (typeof privateKey === 'string') ? new Uint8Array(hexToBuf(privateKey)) : privateKey
    const signingKey = new SigningKey(privKey)
    this.signer = new Wallet(signingKey, provider)
  }

  async signTransaction (transaction: TransactionRequest): Promise<string> {
    return await this.signer.signTransaction(transaction)
  }
}
