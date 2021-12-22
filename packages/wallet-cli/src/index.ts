import readline from 'readline'
import http from 'http'
import { stdin, stdout } from 'process'
import { WalletProtocol, HttpResponderTransport, constants } from '@i3m/wallet-protocol'

const PAIRING_COMMAND='pairing'

const main = async () => {
  const executor = new HttpResponderTransport({
    port: constants.INITIAL_PORT + 12
  })
  const protocol = new WalletProtocol(executor)
  protocol.on('connString', (connString) => {
    console.log(`PIN: ${connString.toString()}`)
  })
  protocol.on('masterKey', (masterKey) => {
    console.log(`MasterKey:`, masterKey)
  })

  const server = http.createServer(async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Request-Method', '*')
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET')
    res.setHeader('Access-Control-Allow-Headers', '*')
    if ( req.method === 'OPTIONS' ) {
      res.writeHead(200)
      res.end()
      return
    } else {
      const forWalletProtocol = await executor.dispatchRequest(req, res)
      if (forWalletProtocol) {
        return
      }
    }

    res.writeHead(404)
    res.end()
  })
  await new Promise<void>((resolve) => server.listen(executor.port, resolve))

  const rl = readline.createInterface({
    input: stdin,
    output: stdout,
    completer(line: string) {
      const completions = [PAIRING_COMMAND];
      const hits = completions.filter((c) => c.startsWith(line));
      
      // show all completions if none found
      return [hits.length ? hits : completions, line];
    } 
  })
  
  const realLog = console.log
  console.log = (...args) => {
    stdout.cursorTo(0)
    realLog(...args)
    rl.prompt()
  }

  rl.setPrompt('> ')
  rl.prompt()
  rl.on('line', (line) => {
    switch(line) {
      case PAIRING_COMMAND:
        protocol.run().then(() => {
          rl.prompt()
        }).catch((reason) => {
          console.log(reason)
        })
        break

      case '':
        rl.prompt()
        break

      default:
        console.log('unknown command')
        rl.prompt()
    }
  })
}
main()
