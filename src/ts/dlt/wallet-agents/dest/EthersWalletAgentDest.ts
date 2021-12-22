import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'
import { ethers } from 'ethers'
import { EthersWalletAgent } from '../EthersWalletAgent'
import { NrError } from '../../../errors'
import { parseHex } from '../../../utils'
import { WalletAgentDest } from './WalletAgentDest'

/**
 * A ledger signer using an ethers.io Wallet.
 */
export class EthersWalletAgentDest extends EthersWalletAgent implements WalletAgentDest {
  async getSecretFromLedger (signerAddress: string, exchangeId: string, timeout: number): Promise<{ hex: string, iat: number }> {
    let secretBn = ethers.BigNumber.from(0)
    let timestampBn = ethers.BigNumber.from(0)
    const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId) as ArrayBuffer), true)
    let counter = 0
    do {
      try {
        ({ secret: secretBn, timestamp: timestampBn } = await this.contract.registry(parseHex(signerAddress, true), exchangeIdHex))
      } catch (error) {
        throw new NrError(error, ['cannot contact the ledger'])
      }
      if (secretBn.isZero()) {
        counter++
        await new Promise(resolve => setTimeout(resolve, 1000))
      }
    } while (secretBn.isZero() && counter < timeout)
    if (secretBn.isZero()) {
      throw new NrError(new Error(`timeout of ${timeout}s exceeded when querying the ledger and secret still not published`), ['secret not published'])
    }
    const hex = parseHex(secretBn.toHexString(), false)
    const iat = timestampBn.toNumber()

    return { hex, iat }
  }
}
