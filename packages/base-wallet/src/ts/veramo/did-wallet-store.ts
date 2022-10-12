import { IIdentifier } from '@veramo/core'
import { AbstractDIDStore } from '@veramo/did-manager'
import Debug from 'debug'

import { BaseWalletModel, Store } from '../app'
import { WalletError } from '../errors'

const debug = Debug('base-wallet:DidWalletStore')

export default class DIDWalletStore<T extends BaseWalletModel> extends AbstractDIDStore {
  constructor (protected store: Store<T>) {
    super()
  }

  async import (args: IIdentifier): Promise<boolean> {
    await this.store.set(`identities.${args.did}`, args)
    return true
  }

  get (args: { did: string }): Promise<IIdentifier>
  get (args: { alias: string, provider: string }): Promise<IIdentifier>
  async get (args: any): Promise<IIdentifier> {
    debug('Get ddo')
    const ddos = await this.store.get('identities', {})
    if (args.did !== undefined) {
      if (ddos[args.did] === undefined) {
        throw new WalletError('DID not found', { status: 404 })
      }
      return ddos[args.did]
    } else if (args.alias !== undefined) {
      throw new WalletError('Get by alias not implemented.', { status: 500 })
    } else {
      const dids = Object.keys(ddos)
      if (dids.length === 0) {
        throw new WalletError('DID not found', { status: 404 })
      }
      return ddos[dids[0]] // Return a random ddo
    }
  }

  async delete (args: { did: string }): Promise<boolean> {
    await this.store.delete(`identities.${args.did}`)
    return true
  }

  async list (args: { alias?: string | undefined, provider?: string | undefined }): Promise<IIdentifier[]> {
    const dids = await this.store.get('identities')
    if (dids === undefined) {
      return []
    }

    const { alias, provider } = args
    return Object.keys(dids).filter((did) => {
      if (alias !== undefined && dids[did].alias !== alias) {
        return false
      }
      if (provider !== undefined && dids[did].provider !== provider) {
        return false
      }
      return true
    }).map(did => dids[did])
  }
}
