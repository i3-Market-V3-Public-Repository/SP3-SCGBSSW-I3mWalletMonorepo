import { ethers } from 'ethers'
import { NrError } from '../errors/index.js'

export function getDltAddress (didOrKeyInHex: string): string {
  const didRegEx = /^did:ethr:(\w+:)?(0x[0-9a-fA-F]{40}[0-9a-fA-F]{26}?)$/
  const match = didOrKeyInHex.match(didRegEx)
  const key = (match !== null) ? match[match.length - 1] : didOrKeyInHex

  try {
    return ethers.utils.computeAddress(key)
  } catch (error) {
    throw new NrError('no a DID or a valid public or private key', ['invalid format'])
  }
}
