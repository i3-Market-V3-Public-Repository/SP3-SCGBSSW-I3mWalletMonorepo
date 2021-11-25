// create TLS client
client = forge.tls.createConnection({
  server: false,
  caStore: [],
  sessionCache: {},
  // supported cipher suites in order of preference
  cipherSuites: [
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
  virtualHost: 'example.com',
  verify: function(connection, verified, depth, certs) {
    if(depth === 0) {
      var cn = certs[0].subject.getField('CN').value;
      if(cn !== 'example.com') {
        verified = {
          alert: forge.tls.Alert.Description.bad_certificate,
          message: 'Certificate common name does not match hostname.'
        };
      }
    }
    return verified;
  },
  connected: function(connection) {
    console.log('connected');
    // send message to server
    connection.prepare(forge.util.encodeUtf8('Hi server!'));
    /* NOTE: experimental, start heartbeat retransmission timer
    myHeartbeatTimer = setInterval(function() {
      connection.prepareHeartbeatRequest(forge.util.createBuffer('1234'));
    }, 5*60*1000);*/
  },
  /* provide a client-side cert if you want
  getCertificate: function(connection, hint) {
    return myClientCertificate;
  },
  /* the private key for the client-side cert if provided */
  getPrivateKey: function(connection, cert) {
    return myClientPrivateKey;
  },
  tlsDataReady: function(connection) {
    // TLS data (encrypted) is ready to be sent to the server
    // sendToServerSomehow(connection.tlsData.getBytes());
    
    // if you were communicating with the server below, you'd do:
    // server.process(connection.tlsData.getBytes());
  },
  dataReady: function(connection) {
    // clear data from the server is ready
    console.log('the server sent: ' +
      forge.util.decodeUtf8(connection.data.getBytes()));
    // close connection
    connection.close();
  },
  /* NOTE: experimental
  heartbeatReceived: function(connection, payload) {
    // restart retransmission timer, look at payload
    clearInterval(myHeartbeatTimer);
    myHeartbeatTimer = setInterval(function() {
      connection.prepareHeartbeatRequest(forge.util.createBuffer('1234'));
    }, 5*60*1000);
    payload.getBytes();
  },*/
  closed: function(connection) {
    console.log('disconnected');
  },
  error: function(connection, error) {
    console.log('uh oh', error);
  }
});
 
// start the handshake process
client.handshake();
 
// when encrypted TLS data is received from the server, process it
// client.process(encryptedBytesFromServer);





////////////////////////////////////////////////
function _arrayBufferToBase64( buffer ) {
  var binary = '';
  var bytes = new Uint8Array( buffer );
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
      binary += String.fromCharCode( bytes[ i ] );
  }
  return window.btoa( binary );
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}

// @juanelas/base64
// base64 sin padding y cambiando (0 O I l) por ($ # % &)
// cifrador: aes-256-gcm
// sha-256 y pbkdf2-hmac con salt a 0, iteraciones 1 y dklen (juanelas)
// https://github.com/juanelas/pbkdf2-hmac
// object-sha
const MAP = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const base58 = {
  encode: function(B,A){var d=[],s="",i,j,c,n;for(i in B){j=0,c=B[i];s+=c||s.length^i?"":1;while(j in d||c){n=d[j];n=n?n*256+c:c;c=n/58|0;d[j]=n%58;j++}}while(j--)s+=A[d[j]];return s},
  decode: function(S,A){var d=[],b=[],i,j,c,n;for(i in S){j=0,c=A.indexOf(S[i]);if(c<0)return undefined;c||b.length^i?i:b.push(0);while(j in d||c){n=d[j];n=n?n*58+c:c;c=n>>8;d[j]=n%256;j++}}while(j--)b.push(d[j]);return new Uint8Array(b)}
}
const l = 36

const { WalletProtocol, HttpInitiatorTransport } = walletProtocol

const main = async () => {
  const input = document.getElementById('code-input')
  const button = document.getElementById('protocol-button')

  const getConnectionString = async () => {
    return input.value
  }

  const executor = new HttpInitiatorTransport({ getConnectionString })
  const protocol = new WalletProtocol(executor)
  protocol.on('masterKey', console.log)

  button.addEventListener('click', async () => {
    console.log('Start protocol')
    await protocol.run()
  })
}
window.onload = main