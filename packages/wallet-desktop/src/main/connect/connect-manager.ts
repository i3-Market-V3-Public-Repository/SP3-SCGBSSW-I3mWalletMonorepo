import http from 'http'
import { WalletError } from '@i3m/base-wallet'
import { WalletProtocol, HttpResponderTransport, Identity } from '@i3m/wallet-protocol'

import { Locals, MainContext } from '@wallet/main/internal'
import { cors } from './cors'
import { JwtCodeGenerator } from './code-generator'
import { KeyLike, errors, JWK, importJWK } from 'jose'

interface Params {
  key: KeyLike | Uint8Array
}

export class ConnectManager {
  protected walletProtocol: WalletProtocol
  public walletProtocolTransport: HttpResponderTransport

  static async initialize (ctx: MainContext, locals: Locals): Promise<ConnectManager> {
    const { sharedMemoryManager: shm } = locals

    const jwk = shm.memory.settings.private.secret as JWK
    const key = await importJWK(jwk, 'HS256')
    return new ConnectManager(locals, { key }) // no se puede
  }

  constructor (protected locals: Locals, params: Params) {
    const id: Identity = {
      name: 'Wallet desktop'
    }
    const codeGenerator = new JwtCodeGenerator(params.key, locals)
    const httpTransport = new HttpResponderTransport({
      id,
      codeGenerator,
      timeout: 60000
    })
    this.walletProtocol = new WalletProtocol(httpTransport)
    this.walletProtocolTransport = httpTransport
    this.handleRequest = this.handleRequest.bind(this)
    this.bindWalletProtocolEvents()
  }

  bindWalletProtocolEvents (): void {
    const { sharedMemoryManager } = this.locals

    this.walletProtocol
      .on('connString', (connString) => {
        sharedMemoryManager.update((mem) => ({
          ...mem,
          connectData: {
            ...mem.connectData,
            walletProtocol: {
              ...mem.connectData.walletProtocol,
              connectString: connString.toString()
            }
          }
        }))
      })
      .on('finished', () => {
        sharedMemoryManager.update((mem) => ({
          ...mem,
          connectData: {
            ...mem.connectData,
            walletProtocol: {
              ...mem.connectData.walletProtocol,
              connectString: undefined
            }
          }
        }))
      })
  }

  handleRequest (req: http.IncomingMessage, res: http.ServerResponse): void {
    const _run = async (): Promise<void> => {
      if (cors(req, res)) {
        return
      }

      await this.walletProtocolTransport.dispatchRequest(req, res)
    }

    _run().catch((err) => {
      if (err instanceof WalletError) {
        res.statusCode = err.status
        res.end(JSON.stringify(err))
        return
      } else if (err instanceof errors.JWTExpired || err instanceof errors.JWEInvalid) {
        res.statusCode = 401
        res.end(JSON.stringify({
          reason: 'Unauthorized token'
        }))
        return
      } else if (err instanceof Error) {
        res.statusCode = 500
        res.end(JSON.stringify({
          reason: err.message
        }))
      } else {
        res.statusCode = 500
        res.end(JSON.stringify(err))
      }
      throw err
    })
  }

  startWalletProtocol (): void {
    this.walletProtocol.run().then(() => {
      // Pairing correct
      this.locals.windowManager.openMainWindow('/wallet/explorer')
      this.locals.toast.show({
        message: 'Successful pairing',
        type: 'success'
      })
    }).catch((err) => {
      // Pairing failed
      this.locals.toast.show({
        message: 'Unsuccessful pairing',
        type: 'error'
      })
      throw err
    })
  }
}
