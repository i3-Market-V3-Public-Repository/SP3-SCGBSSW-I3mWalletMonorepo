import { KeyLike, TypedArray } from '../utils'

export interface KeyWallet<T extends TypedArray = Uint8Array> {
  /**
   * Creates a key pair
   *
   * @returns a promise that resolves to the key id.
   */
  createAccountKeyPair: () => Promise<string>

  /**
   * Gets a public key
   *
   * @returns a promise that resolves to a public key
   */
  getPublicKey: (id: string) => Promise<KeyLike>

  /**
   * Signs input message and returns DER encoded typed array
   */
  signDigest: (id: string, message: T) => Promise<T>

  /**
   * @throws Error - Any error
   */
  delete: (id: string) => Promise<boolean>

  /**
   * @throws Error - Any error
   */
  wipe: () => Promise<void>
}
