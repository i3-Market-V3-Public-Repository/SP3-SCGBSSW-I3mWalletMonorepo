import { WalletComponents } from '@i3m/wallet-desktop-openapi/types'
import { IIdentifier } from '@veramo/core'
import { CanBePromise } from '../utils'

export type Resource = WalletComponents.Schemas.Resource & WalletComponents.Schemas.ResourceId & { identity?: WalletComponents.Schemas.ObjectResource['identity']} & {parentResource?: WalletComponents.Schemas.ObjectResource['parentResource']}
export type VerifiableCredentialResource = Resource & { type: 'VerifiableCredential' }
export type ObjectResource = Resource & { type: 'Object' }
export type KeyPairResource = Resource & { type: 'KeyPair' }
export type ContractResource = Resource & { type: 'Contract' }
export type NonRepudiationProofResource = Resource & { type: 'NonRepudiationProof' }
export type DataExchangeResource = Resource & { type: 'DataExchange' }

export type VerifiableCredential = WalletComponents.Schemas.VerifiableCredential['resource']
export type KeyPair = WalletComponents.Schemas.KeyPair['resource']
export type Contract = WalletComponents.Schemas.Contract['resource']
export type Object = WalletComponents.Schemas.ObjectResource['resource']
export type Identity = IIdentifier

export interface BaseWalletModel {
  resources: {
    [id: string]: Resource
  }
  identities: {
    [did: string]: Identity
  }
}

export interface Store<T extends Record<string, any> = Record<string, unknown>> {
  /**
   * Get an item.
   *
   * @param key - The key of the item to get.
   * @param defaultValue - The default value if the item does not exist.
  */
  get<Key extends keyof T>(key: Key): CanBePromise<T[Key]> // eslint-disable-line @typescript-eslint/method-signature-style
  get<Key extends keyof T>(key: Key, defaultValue: Required<T>[Key]): CanBePromise<Required<T>[Key]> // eslint-disable-line @typescript-eslint/method-signature-style

  /**
   * Set multiple keys at once.
   * @param store
   */
  set(store: Partial<T>): CanBePromise<void> // eslint-disable-line @typescript-eslint/method-signature-style
  /**
   * Set an item.
   * @param key - The key of the item to set
   * @param value - The value to set
   */
  set<Key extends keyof T>(key: Key, value: T[Key]): CanBePromise<void> // eslint-disable-line @typescript-eslint/method-signature-style
  set(key: string, value: unknown): CanBePromise<void> // eslint-disable-line @typescript-eslint/method-signature-style

  /**
   * Check if an item exists.
   *
   * @param key - The key of the item to check.
   */
  has<Key extends keyof T>(key: Key): CanBePromise<boolean> // eslint-disable-line @typescript-eslint/method-signature-style
  has(key: string): CanBePromise<boolean> // eslint-disable-line @typescript-eslint/method-signature-style

  /**
   * Delete an item.
   * @param key - The key of the item to delete.
   */
  delete<Key extends keyof T>(key: Key): CanBePromise<void> // eslint-disable-line @typescript-eslint/method-signature-style
  delete(key: string): CanBePromise<void> // eslint-disable-line @typescript-eslint/method-signature-style

  /**
   * Delete all items.
   */
  clear: () => CanBePromise<void>

  /**
   * Return a readonly version of the complete store
   * @returns The entire store
   */
  getStore: () => CanBePromise<T>

  /**
   * Get the path of the store
   * @returns The store path
   */
  getPath: () => string
}
