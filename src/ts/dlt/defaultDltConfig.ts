import { ContractConfig, DltConfig } from '../types'
/** TO-DO: Could the json be imported from an npm package? */
import contractConfig from '@i3m/non-repudiation-protocol-smart-contract'

export const defaultDltConfig: DltConfig = {
  gasLimit: 12500000,
  rpcProviderUrl: '***REMOVED***',
  disable: false,
  contract: contractConfig as ContractConfig
}
