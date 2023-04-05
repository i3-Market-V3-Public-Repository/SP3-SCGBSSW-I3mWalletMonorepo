import { RequestHandler } from 'express'
import { WalletError } from '@i3m/base-wallet'
import { Locals, logger } from '@wallet/main/internal'

export const developerApi = (locals: Locals): RequestHandler => {
  const { sharedMemoryManager } = locals

  return (req: any, res, next) => {
    const developerApi = sharedMemoryManager.memory.settings.private.developer.enableDeveloperApi
    if (!developerApi) {
      if (req.walletProtocol !== true) {
        next(new WalletError('the request must use wallet protocol', { status: 400 }))
      }
    } else {
      logger.warn('Using developer api. Not recommended for production!')
    }
    next()
  }
}
