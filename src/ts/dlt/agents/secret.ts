import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'
import { ethers } from 'ethers'
import { NrpDltAgentOrig } from './orig/index.js'
import { NrError } from '../../errors/index.js'
import { parseHex } from '../../utils/index.js'
import { EthersIoAgent } from './EthersIoAgent.js'

export async function getSecretFromLedger (contract: ethers.Contract, signerAddress: string, exchangeId: string, timeout: number, secretLength: number): Promise<{ hex: string, iat: number }> {
  let secretBn = ethers.BigNumber.from(0)
  let timestampBn = ethers.BigNumber.from(0)
  const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId) as ArrayBuffer), true)
  let counter = 0
  do {
    try {
      ({ secret: secretBn, timestamp: timestampBn } = await contract.registry(parseHex(signerAddress, true), exchangeIdHex))
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
  const hex = parseHex(secretBn.toHexString(), false, secretLength)
  const iat = timestampBn.toNumber()

  return { hex, iat }
}

export async function secretUnisgnedTransaction (secretHex: string, exchangeId: string, agent: EthersIoAgent & NrpDltAgentOrig): Promise<ethers.UnsignedTransaction> {
  const secret = ethers.BigNumber.from(parseHex(secretHex, true))
  const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId) as Uint8Array), true)

  const unsignedTx = await agent.contract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: agent.dltConfig.gasLimit }) as any
  unsignedTx.nonce = await agent.nextNonce()
  unsignedTx.gasLimit = unsignedTx.gasLimit?._hex
  unsignedTx.gasPrice = (await agent.provider.getGasPrice())._hex
  unsignedTx.chainId = (await agent.provider.getNetwork()).chainId
  const address = await agent.getAddress()
  unsignedTx.from = parseHex(address, true)

  return unsignedTx
}
