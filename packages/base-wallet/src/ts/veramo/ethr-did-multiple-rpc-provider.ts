import type { BlockTag } from '@ethersproject/abstract-provider'
import type { DIDDocument, DIDResolutionOptions, DIDResolutionResult, DIDResolver, ParsedDID, Resolvable } from 'did-resolver'
import type { BigNumber } from 'ethers'
import { multipleExecutions, MultipleExecutionsOptions } from '../utils'
import { allEqual } from '../utils/all-equal'
import type { ProviderConfiguration } from './ethr-did-resolver_DO-NOT-EDIT/configuration'
import type { ERC1056Event } from './ethr-did-resolver_DO-NOT-EDIT/helpers'
import { EthrDidResolver } from './ethr-did-resolver_DO-NOT-EDIT/resolver'
import type { ProviderData } from './veramo'

export interface ConfigurationOptions {
  networks: ProviderData[]
  multiRpcOptions?: MultipleExecutionsOptions
}

export function getResolver (options: ConfigurationOptions): Record<string, DIDResolver> {
  return new EthrDidMultipleRpcResolver(options).build()
}

export class EthrDidMultipleRpcResolver implements Omit<EthrDidResolver, 'contracts'> {
  resolvers: EthrDidResolver[]
  networks: ProviderData[]
  multiRpcOptions: MultipleExecutionsOptions

  constructor (protected options: ConfigurationOptions) {
    this.resolvers = []
    const providerConfs: ProviderConfiguration[][] = []
    options.networks.forEach(conf => {
      if (conf.rpcUrl instanceof Array) {
        conf.rpcUrl.forEach((rpcUrl, index) => {
          if (providerConfs[index] === undefined) providerConfs[index] = []
          providerConfs[index].push({
            name: conf.network,
            rpcUrl: rpcUrl
          })
        })
      } else {
        if (providerConfs[0] === undefined) providerConfs[0] = []
        providerConfs[0].push({
          name: conf.network,
          rpcUrl: conf.rpcUrl
        })
      }
    })
    providerConfs.forEach(conf => {
      const resolver = new EthrDidResolver({
        networks: conf
      })
      this.resolvers.push(resolver)
    })
    if (this.resolvers.length === 0) {
      throw new Error('no networks')
    }

    this.networks = options.networks
    this.multiRpcOptions = options.multiRpcOptions ?? {}
  }

  async getOwner (address: string, networkId: string, blockTag?: BlockTag | undefined): Promise<string> {
    // return await this.resolvers[0].getOwner(address, networkId, blockTag)
    return await this.multiproviderFnExec('getOwner', address, networkId, blockTag)
  }

  async previousChange (address: string, networkId: string, blockTag?: BlockTag | undefined): Promise<BigNumber> {
    return await this.multiproviderFnExec('previousChange', address, networkId, blockTag)
  }

  async getBlockMetadata (blockHeight: number, networkId: string): Promise<{ height: string, isoDate: string }> {
    return await this.multiproviderFnExec('getBlockMetadata', blockHeight, networkId)
  }

  async changeLog (identity: string, networkId: string, blockTag?: BlockTag | undefined): Promise<{ address: string, history: ERC1056Event[], controllerKey?: string | undefined, chainId: number }> {
    return await this.multiproviderFnExec('changeLog', identity, networkId, blockTag)
  }

  wrapDidDocument (did: string, address: string, controllerKey: string | undefined, history: ERC1056Event[], chainId: number, blockHeight: string | number, now: BigNumber): { didDocument: DIDDocument, deactivated: boolean, versionId: number, nextVersionId: number } {
    return this.resolvers[0].wrapDidDocument(did, address, controllerKey, history, chainId, blockHeight, now)
  }

  async resolve (did: string, parsed: ParsedDID, _unused: Resolvable, options: DIDResolutionOptions): Promise<DIDResolutionResult> {
    return await this.multiproviderFnExec('resolve', did, parsed, _unused, options)
  }

  build (): Record<string, DIDResolver> {
    return { ethr: this.resolve.bind(this) }
  }

  private async multiproviderFnExec<T> (fnName: string, ...args: any[]): Promise<T> {
    const results = await multipleExecutions<T>(this.multiRpcOptions, this.resolvers, fnName, ...args)
    if (allEqual(results)) return results[0]
    throw new Error('not all responses are equal, please consider removing the missbehaving/malicious RPC endpoint.')
  }
}
