
import { ScryptParams } from 'scrypt-pbkdf'
import { KeyObject } from 'crypto'

// *** Authentication ***

export interface UndefinedAuthSettings {
  algorithm: undefined
  salt: string
  localAuth?: string
}

export interface Pbkdf2AuthSettings {
  algorithm: 'pbkdf.2'
  salt: string
  localAuth?: string
}

export type AuthSettings = UndefinedAuthSettings | Pbkdf2AuthSettings
export type AuthSettingsAlgorithms = AuthSettings['algorithm']

// *** Encryption ***

export interface Pbkdf2EncSettings {
  algorithm: 'pbkdf.2'
  salt: string
}

export type PbkdfAlgorithms = 'scrypt' | 'pbkdf2'
export type PbkdfInput = 'password' | 'master'
export type HashFunction = "sha256" | "sha512"
export type KeyIdentifiers = 'master' | 'settings' | 'wallet'
export type Pbkdf2Params = {
  iterations: number
}

export type AlgorithmOptionsFor<Alg extends PbkdfAlgorithms> = {
  scrypt: ScryptParams
  pbkdf2: Pbkdf2Params
}[Alg]

export type KeyDerivationContext = Record<string, string | KeyObject | Buffer | undefined>
export type KeyDerivation<Alg extends PbkdfAlgorithms = PbkdfAlgorithms> = {
  alg: Alg
  derived_key_length: number,
  input_pattern: string,
  salt_pattern: string,
  salt_hashing_algorithm: HashFunction,
  alg_options: AlgorithmOptionsFor<Alg>
}

export type KeyDerivationMap<K extends string> = {
  [P in K]: KeyDerivation
}

export interface GenericPbkdfEncSettings {
  algorithm: 'generic-pbkdf'
  salt: string
  key_derivation: KeyDerivationMap<KeyIdentifiers>
}

export type EncSettings = Pbkdf2EncSettings | GenericPbkdfEncSettings
export type EncSettingsAlgorithms = EncSettings['algorithm']
