import readline from 'readline'
import http from 'http'
import { stdin, stdout } from 'process'
import { WalletProtocol, HttpResponderTransport, constants } from '@i3-market/wallet-protocol'

const PAIRING_COMMAND='pairing'

const main = async () => {
  const server = http.createServer((req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Request-Method', '*')
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET')
    res.setHeader('Access-Control-Allow-Headers', '*')
    if ( req.method === 'OPTIONS' ) {
      res.writeHead(200);
      res.end();
      
      return;
    }
  })
  const port = constants.INITIAL_PORT + 12
  server.listen(port)

  const executor = new HttpResponderTransport(server, { port })
  const protocol = new WalletProtocol(executor)
  protocol.on('connString', (connString) => {
    console.log(`PIN: ${connString.toString()}`)
  })
  protocol.on('masterKey', (masterKey) => {
    console.log(`MasterKey:`, masterKey)
  })

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
