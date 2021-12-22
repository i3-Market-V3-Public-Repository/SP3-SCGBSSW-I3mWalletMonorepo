import http from 'http'
import { WalletError } from '@i3m/base-wallet'
import { WalletProtocol, HttpResponderTransport, Identity } from '@i3m/wallet-protocol'

import { Locals } from '@wallet/main/internal'
import { cors } from './cors'
import { JwtCodeGenerator } from './code-generator'
import { KeyLike } from 'jose'

export class ConnectManager {
  protected walletProtocol: WalletProtocol
  public walletProtocolTransport: HttpResponderTransport

  constructor (protected locals: Locals, key: KeyLike | Uint8Array) {
    const id: Identity = {
      name: 'Wallet desktop'
    }
    const codeGenerator = new JwtCodeGenerator(key, locals)
    const httpTransport = new HttpResponderTransport({
      id,
      codeGenerator,
      timeout: 60000
    })
    this.walletProtocol = new WalletProtocol(httpTransport)
    this.walletProtocolTransport = httpTransport
    this.handleRequest = this.handleRequest.bind(this)
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

  async initialize (): Promise<void> {
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

  startWalletProtocol (): void {
    this.walletProtocol.run().then(() => {
      // Pairing correct
    }).catch((err) => {
      // Pairing failed
      throw err
    })
  }
}
