
export interface MainArgs {
  name: 'Main'
  path: string
}

export interface SignArgs {
  name: 'Sign'
  accountId: string
}

export interface PasswordArgs {
  name: 'Password'
}

export type WindowArgs = MainArgs | SignArgs | PasswordArgs
