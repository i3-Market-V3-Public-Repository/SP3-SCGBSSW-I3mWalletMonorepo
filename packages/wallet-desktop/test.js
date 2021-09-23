
const https = require('https')

const cipher = 'tls_aes_128_gcm_sha256'.toUpperCase()
console.log(cipher)
const key = Buffer.from('1b0d885fb69527dd11bea699be51af19', 'hex')
console.log(key.toString('hex'))

const options = {
  ciphers: cipher,
  pskCallback: (socket, identity) => {
    return key
  }
}

https.createServer(options, (req, res) => {
  res.writeHead(200)
  res.end('hello world\n')
}).listen(9080, () => {
  console.log('Server ready')
}).on('tlsClientError', (err, tlsSocket) => {
  console.error(err)
}).on('secureConnection', () => {
  console.log('connected')
})
