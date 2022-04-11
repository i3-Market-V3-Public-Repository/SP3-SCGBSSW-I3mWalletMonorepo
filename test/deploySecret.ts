import { randBytes } from 'bigint-crypto-utils'
import ethersWalletSetup from './ethersWalletSetup.json'

describe('Non-repudiation protocol', function () {
  this.timeout(2000000)
  const SIGNING_ALG: _pkg.SigningAlg = 'ES256'

  let providerWallet: _pkg.EthersWalletAgentOrig
  let providerJwks: _pkg.JwkPair

  let consumerWallet: _pkg.EthersWalletAgentDest
  let consumerJwks: _pkg.JwkPair

  let nrpProvider: _pkg.NonRepudiationProtocol.NonRepudiationOrig
  let nrpConsumer: _pkg.NonRepudiationProtocol.NonRepudiationDest
  let dataExchangeAgreement: _pkg.DataExchangeAgreement

  this.beforeAll(async () => {
    consumerWallet = new _pkg.EthersWalletAgentDest()
    consumerJwks = await _pkg.generateKeys('ES256')

    providerWallet = new _pkg.EthersWalletAgentOrig(ethersWalletSetup.privateKey)
    providerJwks = await _pkg.generateKeys('ES256')

    dataExchangeAgreement = {
      orig: JSON.stringify(providerJwks.publicJwk),
      dest: JSON.stringify(consumerJwks.publicJwk),
      encAlg: 'A256GCM',
      signingAlg: SIGNING_ALG,
      hashAlg: 'SHA-256',
      ledgerContractAddress: '0x8d407a1722633bdd1dcf221474be7a44c05d7c2f',
      ledgerSignerAddress: ethersWalletSetup.address,
      pooToPorDelay: 10000,
      pooToPopDelay: 30000,
      pooToSecretDelay: 180000 // 3 minutes
    }
  })

  describe('deploySecret', function () {
    it('the provider publishes the secret to the DLT and the consumer properly gets it', async function () {
      const block = new Uint8Array(await randBytes(256))
      nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, providerWallet)
      await nrpProvider.initialized
      await nrpProvider.wallet.deploySecret(nrpProvider.block.secret.hex, nrpProvider.exchange.id)

      nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerWallet)
      await nrpConsumer.initialized
      const timeout = Math.round(nrpConsumer.agreement.pooToSecretDelay / 1000)
      const secret = await nrpConsumer.wallet.getSecretFromLedger(dataExchangeAgreement.ledgerSignerAddress, nrpProvider.exchange.id, timeout)

      chai.expect(secret.hex).to.equal(nrpProvider.block.secret.hex)
    })
  })

  describe('multiple sequential deploySecret (testing nonces) from the same wallet instance', function () {
    it('the provider sequentially publishes secrets to the DLT and the consumer properly gets them', async function () {
      const nrpProviders: _pkg.NonRepudiationProtocol.NonRepudiationOrig[] = []
      const publishedSecrets: string[] = []
      const retrievedSecrets: string[] = []
      for (let i = 0; i < 3; i++) {
        const block = new Uint8Array(await randBytes(256))
        const nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, providerWallet)
        nrpProviders.push(nrpProvider)
        await nrpProvider.initialized
        await nrpProvider.wallet.deploySecret(nrpProvider.block.secret.hex, nrpProvider.exchange.id)
        publishedSecrets.push(nrpProvider.block.secret.hex)
      }
      for (let i = 0; i < 3; i++) {
        nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerWallet)
        await nrpConsumer.initialized
        const timeout = Math.round(nrpConsumer.agreement.pooToSecretDelay / 1000)
        const secret = await nrpConsumer.wallet.getSecretFromLedger(dataExchangeAgreement.ledgerSignerAddress, nrpProviders[i].exchange.id, timeout)
        retrievedSecrets.push(secret.hex)
      }
      chai.expect(retrievedSecrets).to.eql(publishedSecrets) // deep equality (to.equal would fail always)
    })
  })
  describe('multiple sequential deploySecret (testing nonces) from different instances of the same wallet', function () {
    it('the provider sequentially publishes secrets to the DLT and the consumer properly gets them', async function () {
      const nrpProviders: _pkg.NonRepudiationProtocol.NonRepudiationOrig[] = []
      const publishedSecrets: string[] = []
      const retrievedSecrets: string[] = []
      for (let i = 0; i < 3; i++) {
        const block = new Uint8Array(await randBytes(256))
        const nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, ethersWalletSetup.privateKey)
        nrpProviders.push(nrpProvider)
        await nrpProvider.initialized
        await nrpProvider.wallet.deploySecret(nrpProvider.block.secret.hex, nrpProvider.exchange.id)
        publishedSecrets.push(nrpProvider.block.secret.hex)
      }
      for (let i = 0; i < 3; i++) {
        nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerWallet)
        await nrpConsumer.initialized
        const timeout = Math.round(nrpConsumer.agreement.pooToSecretDelay / 1000)
        const secret = await nrpConsumer.wallet.getSecretFromLedger(dataExchangeAgreement.ledgerSignerAddress, nrpProviders[i].exchange.id, timeout)
        retrievedSecrets.push(secret.hex)
      }
      chai.expect(retrievedSecrets).to.eql(publishedSecrets) // deep equality (to.equal would fail always)
    })
  })
})
