
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

export interface GeneralMcfAuthSettings {
  algorithm: 'general-mcf'
  localAuth?: string
}

export type AuthSettings = UndefinedAuthSettings | Pbkdf2AuthSettings | GeneralMcfAuthSettings
export type AuthSettingsAlgorithms = AuthSettings['algorithm']

// *** Encryption ***

export interface Pbkdf2EncSettings {
  algorithm: 'pbkdf.2'
  salt: string
}

export type PbkdfAlgorithms = 'scrypt' | 'pbkdf2'
export type PbkdfInput = 'password' | 'master'
export type HashFunction = 'sha256' | 'sha512'
export type KeyIdentifiers = 'master' | 'settings' | 'wallet'
export interface Pbkdf2Params {
  iterations: number
}

export type AlgorithmOptionsFor<Alg extends PbkdfAlgorithms> = {
  scrypt: ScryptParams
  pbkdf2: Pbkdf2Params
}[Alg]

export type KeyDerivationContext = Record<string, string | KeyObject | Buffer | undefined>
export interface KeyDerivation<Alg extends PbkdfAlgorithms = PbkdfAlgorithms> {
  alg: Alg
  alg_options: AlgorithmOptionsFor<Alg>
  derived_key_length: number
  input_pattern: string
  salt_pattern: string
  salt_hashing_algorithm: HashFunction
}

export type KeyDerivationMap<K extends string> = {
  [P in K]: KeyDerivation<'pbkdf2'> | KeyDerivation<'scrypt'>
}

export interface GenericPbkdfEncSettings {
  algorithm: 'generic-pbkdf'
  salt: string
  key_derivation: KeyDerivationMap<KeyIdentifiers>
}

export type EncSettings = Pbkdf2EncSettings | GenericPbkdfEncSettings
export type EncSettingsAlgorithms = EncSettings['algorithm']
