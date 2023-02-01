/* global walletProtocol, walletProtocolUtils, alert */
const { WalletProtocol, HttpInitiatorTransport } = walletProtocol
const { pinDialog, SessionManager } = walletProtocolUtils

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

  const transport = new HttpInitiatorTransport({ getConnectionString: pinDialog })

  const protocol = new WalletProtocol(transport)

  const sessionManager = new SessionManager({ protocol })

  sessionManager
    .$session
    // We can subscribe to events when the session is deleted/end and when a new one is created
    .subscribe((session) => {
      if (session !== undefined) {
        console.log('New session loaded')
        sessionState.innerText = 'ON'
      } else {
        console.log('Session deleted')
        sessionState.innerText = 'OFF'
      }
    })

  const startProtocol = async () => {
    // Loads the current stored session (if any). Use it to recover a previously created session
    await sessionManager.loadSession()

    // creates a secure session (if it does not exist yet)
    await sessionManager.createIfNotExists()
  }

  const sessionToClipboard = async () => {
    await navigator.clipboard.writeText(JSON.stringify(sessionManager.session.toJSON()))
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
      console.log('Assuming invalid token... Remove it')
      sessionManager.removeSession()
      sessionManager.createIfNotExists()
    }
  }

  // Load Events
  protocolButton.addEventListener('click', startProtocol)
  sessionButton.addEventListener('click', sessionToClipboard)
  queryButton.addEventListener('click', sendQuery)
  removeButton.addEventListener('click', () => sessionManager.removeSession())

  startProtocol().catch((reason) => {
    throw new Error(reason)
  })
}
window.onload = main
