import * as _pkg from '#pkg'
import { EncryptionAlg, HashAlg, SigningAlg } from '#pkg'
import { randBytes } from 'bigint-crypto-utils'
import { ethers } from 'ethers'

function algByteLength (alg: EncryptionAlg | HashAlg | SigningAlg): number {
  return Number((alg.match(/\d{3}/) as RegExpMatchArray)[0]) / 8
}

describe('Non-repudiation protocol', function () {
  this.timeout(2000000)
  const SIGNING_ALG: _pkg.SigningAlg = 'ES256'

  const rpcProviderUrl = process.env.RPC_PROVIDER_URL as string
  if (rpcProviderUrl === undefined) {
    throw new Error('You need to pass a RPC_PROVIDER_URL as env variable.\nIf you are not using a wallet, you have to provide a valid RPC for connecting to the DLT.')
  }

  const parsedPrivateKey = process.env.PRIVATE_KEY
  if (parsedPrivateKey === undefined) {
    throw new Error('You need to pass a PRIVATE_KEY as env variable. The associated address should also hold balance enough to interact with the DLT')
  }
  const privateKey = _pkg.parseHex(parsedPrivateKey, true)
  const address = ethers.utils.computeAddress(privateKey)

  const ethersWalletSetup = {
    address,
    privateKey,
    rpcProviderUrl
  }

  let providerDltAgent: _pkg.EthersIoAgentOrig
  let providerJwks: _pkg.JwkPair

  let consumerDltAgent: _pkg.EthersIoAgentDest
  let consumerJwks: _pkg.JwkPair

  let nrpProvider: _pkg.NonRepudiationProtocol.NonRepudiationOrig
  let nrpConsumer: _pkg.NonRepudiationProtocol.NonRepudiationDest
  let dataExchangeAgreement: _pkg.DataExchangeAgreement

  this.beforeAll(async () => {
    consumerDltAgent = new _pkg.EthersIoAgentDest({ rpcProviderUrl: ethersWalletSetup.rpcProviderUrl })
    consumerJwks = await _pkg.generateKeys('ES256')

    providerDltAgent = new _pkg.EthersIoAgentOrig({ rpcProviderUrl: ethersWalletSetup.rpcProviderUrl }, ethersWalletSetup.privateKey)
    providerJwks = await _pkg.generateKeys('ES256')

    dataExchangeAgreement = {
      orig: await _pkg.parseJwk(providerJwks.publicJwk, true),
      dest: await _pkg.parseJwk(consumerJwks.publicJwk, true),
      encAlg: 'A256GCM',
      signingAlg: SIGNING_ALG,
      hashAlg: 'SHA-256',
      ledgerContractAddress: ethers.utils.getAddress('0x8d407a1722633bdd1dcf221474be7a44c05d7c2f'),
      ledgerSignerAddress: ethersWalletSetup.address,
      pooToPorDelay: 10000,
      pooToPopDelay: 30000,
      pooToSecretDelay: 180000 // 3 minutes
    }
    console.log(JSON.stringify(dataExchangeAgreement))
  })

  describe('deploySecret', function () {
    this.bail()
    it('the provider publishes the secret to the DLT and the consumer properly gets it', async function () {
      const block = new Uint8Array(await randBytes(256))
      nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, providerDltAgent)
      await nrpProvider.initialized
      await nrpProvider.dltAgent.deploySecret(nrpProvider.block.secret.hex, nrpProvider.exchange.id)

      nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerDltAgent)
      await nrpConsumer.initialized
      const timeout = Math.round(nrpConsumer.agreement.pooToSecretDelay / 1000)
      const secret = await nrpConsumer.dltAgent.getSecretFromLedger(algByteLength(dataExchangeAgreement.encAlg), dataExchangeAgreement.ledgerSignerAddress, nrpProvider.exchange.id, timeout)

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
        const nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, providerDltAgent)
        nrpProviders.push(nrpProvider)
        await nrpProvider.initialized
        await nrpProvider.dltAgent.deploySecret(nrpProvider.block.secret.hex, nrpProvider.exchange.id)
        publishedSecrets.push(nrpProvider.block.secret.hex)
      }
      for (let i = 0; i < 3; i++) {
        nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerDltAgent)
        await nrpConsumer.initialized
        const timeout = Math.round(nrpConsumer.agreement.pooToSecretDelay / 1000)
        const secret = await nrpConsumer.dltAgent.getSecretFromLedger(algByteLength(dataExchangeAgreement.encAlg), dataExchangeAgreement.ledgerSignerAddress, nrpProviders[i].exchange.id, timeout)
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
        const nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, new _pkg.EthersIoAgentOrig({ rpcProviderUrl: ethersWalletSetup.rpcProviderUrl }, ethersWalletSetup.privateKey))
        nrpProviders.push(nrpProvider)
        await nrpProvider.initialized
        await nrpProvider.dltAgent.deploySecret(nrpProvider.block.secret.hex, nrpProvider.exchange.id)
        publishedSecrets.push(nrpProvider.block.secret.hex)
      }
      for (let i = 0; i < 3; i++) {
        nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerDltAgent)
        await nrpConsumer.initialized
        const timeout = Math.round(nrpConsumer.agreement.pooToSecretDelay / 1000)
        const secret = await nrpConsumer.dltAgent.getSecretFromLedger(algByteLength(dataExchangeAgreement.encAlg), dataExchangeAgreement.ledgerSignerAddress, nrpProviders[i].exchange.id, timeout)
        retrievedSecrets.push(secret.hex)
      }
      chai.expect(retrievedSecrets).to.eql(publishedSecrets) // deep equality (to.equal would fail always)
    })
  })
})
