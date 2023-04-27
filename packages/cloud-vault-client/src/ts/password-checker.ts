import { VaultError } from './error'

export interface PasswordStrengthOptions {
  minLength?: number
  uppercase?: boolean
  lowercase?: boolean
  numbers?: boolean
  symbols?: boolean
  allowedSymbols?: string
}

const defaultPasswordStrengthOptions: Required<PasswordStrengthOptions> = {
  minLength: 10,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  allowedSymbols: '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
}

export function passwordCheck (password: string, options?: PasswordStrengthOptions): void {
  const opts: Required<PasswordStrengthOptions> = {
    ...defaultPasswordStrengthOptions,
    ...options
  }
  if (!opts.uppercase && !opts.lowercase && !opts.numbers && !opts.symbols) {
    throw new VaultError('error', new Error('passwords must have at least one of uppercase, lowercase, digits or symbols'))
  }

  const allowedSymbols = opts.allowedSymbols.replaceAll(/([\^\]\\-])/g, '\\$1')

  if (opts.uppercase) {
    if (!/[A-Z]/.test(password)) {
      throw new VaultError('weak-password', 'at least one uppercase letter must be present in the password')
    }
  }

  if (opts.lowercase) {
    if (!/[a-z]/.test(password)) {
      throw new VaultError('weak-password', 'at least one lowercase letter must be present in the password')
    }
  }

  if (opts.numbers) {
    if (!/[0-9]/.test(password)) {
      throw new VaultError('weak-password', 'at least one digit (0-9) must be present in the password')
    }
  }

  if (opts.symbols) {
    const regexp = new RegExp(`[${allowedSymbols}]`)
    if (!regexp.test(password)) {
      throw new VaultError('weak-password', `at least one symbol (${opts.allowedSymbols}) must be present in the password`)
    }
  }

  const regexStr = `^[${opts.uppercase ? 'A-Z' : ''}${opts.lowercase ? 'a-z' : ''}${opts.numbers ? '0-9' : ''}${opts.symbols ? allowedSymbols : ''}]{${opts.minLength},}$`

  const regexp = new RegExp(regexStr)

  if (!regexp.test(password)) {
    throw new VaultError('weak-password', `minimum length is ${opts.minLength}, and the only characters supported are: ${opts.uppercase ? 'A-Z' : ''}${opts.lowercase ? 'a-z' : ''}${opts.numbers ? '0-9' : ''}${opts.symbols ? opts.allowedSymbols : ''}`)
  }
}
