import { app } from 'electron'

import { Locals, logger, WalletDesktopError } from '@wallet/main/internal'
import { CanBePromise } from '@i3m/base-wallet'
import { checkErrorType, VaultError } from '@i3m/cloud-vault-client'

export async function handleVaultErrors (locals: Locals, err: VaultError): Promise<void> {
  const { toast } = locals
  if (checkErrorType(err, 'not-initialized') || checkErrorType(err, 'http-connection-error')) {
    toast.show({
      type: 'error',
      message: 'Cloud Vault',
      details: 'Cannot connect to the vault server.'
    })
  } else if (checkErrorType(err, 'invalid-credentials')) {
    locals.cloudVaultManager.removeCredentials()
    toast.show({
      type: 'error',
      message: 'Cloud Vault',
      details: 'Invalid credentials.'
    })
  }else if (checkErrorType(err, 'unauthorized')) {
    locals.cloudVaultManager.removeCredentials()
    toast.show({
      type: 'error',
      message: 'Cloud Vault',
      details: 'Unauthorized.'
    })
  } else {
    toast.show({
      type: 'error',
      message: 'Cloud Vault',
      details: `${err.message}: ${err.data?.toString() as string ?? 'no data'}; ${err.cause as string ?? 'unknown cause'}`
    })
  }
}

export async function handleWalletDesktopErrors (locals: Locals, err: WalletDesktopError): Promise<void> {
  if (err.resetSettings) {
    // await locals.dialog.confirmation({
    //   title: err.message,
    //   message: [err.message, 'The '].join('\n\n')
    // })
  }

  if (err.critical) {
    await err.showDialog(locals)
    return app.quit()
  } else {
    err.showToast(locals)
  }
}

export async function handleError (locals: Locals, err: unknown): Promise<void> {
  if (err instanceof Error) {
    logger.error(err.stack)
  } else {
    logger.error(err)
  }

  if (err instanceof VaultError) {
    await handleVaultErrors(locals, err)
  } else if (err instanceof WalletDesktopError) {
    await handleWalletDesktopErrors(locals, err)
  } else {
    const anyError = err as any
    locals.toast.show({
      type: 'error',
      message: 'Something went wrong...',
      details: anyError?.message ?? 'And the cause is unknown'
    })
  }
}

export function handleErrorSync (locals: Locals, err: unknown): void {
  handleError(locals, err).catch((err) => {
    logger.error('Something went very very wrong...')
    logger.error(err)
  })
}

export function handleErrorCatch (locals: Locals): Parameters<Promise<void>['catch']> {
  return [async (err) => await handleError(locals, err)]
}

export function handleCanBePromise<T> (locals: Locals, promise: CanBePromise<T>): void {
  if (promise instanceof Promise) {
    handlePromise(locals, promise)
  }
}

export function handlePromise<T> (locals: Locals, promise: Promise<T>): void {
  promise.catch(...handleErrorCatch(locals))
}
