import { WalletError } from '@i3m/base-wallet'
import { HttpResponderTransport, Identity, WalletProtocol } from '@i3m/wallet-protocol'
import http from 'http'

import { handleErrorCatch, Locals, MainContext } from '@wallet/main/internal'
import { errors, importJWK, JWK, KeyLike } from 'jose'
import { JwtCodeGenerator } from './code-generator'
import { cors } from './cors'

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
    const _startWalletProtocol = async (): Promise<void> => {
      if (this.walletProtocol.isRunning) {
        // TODO: Finish the protocol without launching an error and restarting??
        // await this.walletProtocol.finish()

        // Or just do nothing...
        this.locals.toast.show({
          message: 'Already pairing...',
          type: 'warning'
        })
        return
      }

      try {
        await this.walletProtocol.run()
      } catch (err) {
        // Pairing failed
        this.locals.toast.show({
          message: 'Unsuccessful pairing',
          type: 'error'
        })
        return
      }

      // Pairing correct
      this.locals.windowManager.openMainWindow('/wallet/explorer')
      this.locals.toast.show({
        message: 'Successful pairing',
        type: 'success'
      })
    }

    _startWalletProtocol().catch(...handleErrorCatch(this.locals))
  }
}
