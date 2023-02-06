import { RequestHandler } from 'express'
import { WalletError } from '@i3m/base-wallet'
import { Locals, logger } from '@wallet/main/internal'

export const developerApi = async (locals: Locals): Promise<RequestHandler> => {
  const developerSettings = await locals.settings.get('developer')

  return (req: any, res, next) => {
    const developerApi = developerSettings.enableDeveloperApi
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
