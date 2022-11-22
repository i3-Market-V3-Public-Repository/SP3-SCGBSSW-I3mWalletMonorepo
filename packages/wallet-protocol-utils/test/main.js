
// @juanelas/base64
// base64 sin padding y cambiando (0 O I l) por ($ # % &)
// cifrador: aes-256-gcm
// sha-256 y pbkdf2-hmac con salt a 0, iteraciones 1 y dklen (juanelas)
// https://github.com/juanelas/pbkdf2-hmac
// object-sha
// phase3: secret verification
// ultimo kdf pocas iteraciones

const MAP = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const base58 = {
  encode: function(B,A){var d=[],s="",i,j,c,n;for(i in B){j=0,c=B[i];s+=c||s.length^i?"":1;while(j in d||c){n=d[j];n=n?n*256+c:c;c=n/58|0;d[j]=n%58;j++}}while(j--)s+=A[d[j]];return s},
  decode: function(S,A){var d=[],b=[],i,j,c,n;for(i in S){j=0,c=A.indexOf(S[i]);if(c<0)return undefined;c||b.length^i?i:b.push(0);while(j in d||c){n=d[j];n=n?n*58+c:c;c=n>>8;d[j]=n%256;j++}}while(j--)b.push(d[j]);return new Uint8Array(b)}
}

const { WalletProtocol, HttpInitiatorTransport, Session } = walletProtocol
const { openModal, LocalSessionManager } = walletProtocolUtils

const main = async () => {
  const urlInput = document.getElementById('url-input')
  const methodInput = document.getElementById('method-input')
  const bodyInput = document.getElementById('body-input')
  const responseInput = document.getElementById('response-input')
  const sessionState = document.getElementById('session-state')
  const protocolButton = document.getElementById('protocol-button')
  const sessionButton = document.getElementById('session-button')
  const removeButton = document.getElementById('remove-button')
  const queryButton = document.getElementById('query-button')

  const transport = new HttpInitiatorTransport({ getConnectionString: openModal })
  const protocol = new WalletProtocol(transport)
  const sessionManager = new LocalSessionManager(protocol)

  sessionManager
    .$session
    .subscribe((session) => {
      sessionState.innerText = session !== undefined ? 'ON' : 'OFF'
    })

  const startProtocol = async () => {
    await sessionManager.createIfNotExists()
  }

  const sessionToClipboard = async () => {
    await navigator.clipboard.writeText(JSON.stringify(sessionManager.session.toJSON(), null, 2))
  }

  const sendQuery = async () => {
    if (!sessionManager.hasSession) {
      alert('no session yet')
      return
    }

    const body = bodyInput.value
    const headers = {}
    if (body) {
      headers['Content-Type'] = 'application/json'
    }

    try {
      const resp = await sessionManager.fetch(urlInput.value, {
        method: methodInput.value,
        headers: headers,
        body
      })
      if (resp.status < 300 && resp.status >= 200) {
        const json = JSON.parse(resp.body)
        responseInput.value = JSON.stringify(json, null, 2)
      } else {
        responseInput.value = `ERROR: ${resp.status} ${resp.statusText}`
      }
    } catch (e) {
      console.log("Assuming invalid token... Remove it")
      sessionManager.removeSession()
      sessionManager.createIfNotExists()
      return
    }
  }

  // Load Events
  protocolButton.addEventListener('click', startProtocol)
  sessionButton.addEventListener('click', sessionToClipboard)
  queryButton.addEventListener('click', sendQuery)
  removeButton.addEventListener('click', () => sessionManager.removeSession())

  //
  await sessionManager.loadSession()
  await sessionManager.createIfNotExists()
}
window.onload = main
