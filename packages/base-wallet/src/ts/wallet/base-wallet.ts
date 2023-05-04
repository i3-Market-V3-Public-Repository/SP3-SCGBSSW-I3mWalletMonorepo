/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { IIdentifier, IMessage, VerifiableCredential, VerifiablePresentation } from '@veramo/core'
import { ethers } from 'ethers'
import _ from 'lodash'
import * as u8a from 'uint8arrays'
import { v4 as uuid } from 'uuid'
import { decodeJWS, jwsSignInput } from '../utils/jws'

import { BaseWalletModel, DataExchangeResource, DescriptorsMap, Dialog, DialogOptionContext, Identity, KeyPairResource, Resource, Store, Toast } from '../app'
import { WalletError } from '../errors'
import { KeyWallet } from '../keywallet'
import { ResourceValidator } from '../resource'
import { getCredentialClaims, multipleExecutions } from '../utils'
import { didJwtVerify as didJwtVerifyFn } from '../utils/did-jwt-verify'
import { displayDid } from '../utils/display-did'
import { Veramo, DEFAULT_PROVIDER, DEFAULT_PROVIDERS_DATA, ProviderData } from '../veramo'

import { exchangeId, NrProofPayload } from '@i3m/non-repudiation-library'
import Debug from 'debug'
import { digest } from 'object-sha'
import { Wallet } from './wallet'
import { WalletFunctionMetadata } from './wallet-metadata'
import { WalletOptions } from './wallet-options'
import { shuffleArray } from '../utils/shuffle-array'

const debug = Debug('base-wallet:base-wallet.ts')

interface SdrClaim {
  claimType: string
  essential: boolean | undefined
}

interface SelectiveDisclosureData {
  claims: SdrClaim[]
}

interface CandidateClaim extends SdrClaim {
  credentials: VerifiableCredential[]
}

interface CandidateIdentity {
  [claimType: string]: CandidateClaim
}

interface CandidateIdentities {
  [did: string]: CandidateIdentity
}

interface VerifiableCredentialMap {
  [k: string]: VerifiableCredential
}

interface SelectIdentityOptions {
  reason?: string
}

interface TransactionData {
  from: IIdentifier
  to: string
  value: string
  sign: boolean
}

interface TransactionOptions {
  transaction?: string
  notifyUser?: boolean
}

type ResourceMap = BaseWalletModel['resources']

export class BaseWallet<
  Options extends WalletOptions<Model>,
  Model extends BaseWalletModel = BaseWalletModel
> implements Wallet {
  public dialog: Dialog
  public store: Store<Model>
  public toast: Toast
  public veramo: Veramo<Model>

  protected keyWallet: KeyWallet
  protected resourceValidator: ResourceValidator
  protected provider: string
  protected providersData: Record<string, ProviderData>
  protected confirmations: Record<string, boolean>

  constructor (opts: Options) {
    this.dialog = opts.dialog
    this.store = opts.store
    this.toast = opts.toast
    this.keyWallet = opts.keyWallet
    this.resourceValidator = new ResourceValidator()
    this.provider = opts.provider ?? DEFAULT_PROVIDER
    this.providersData = opts.providersData ?? DEFAULT_PROVIDERS_DATA
    this.confirmations = {}

    // Init veramo framework
    this.veramo = new Veramo(this.store, this.keyWallet, this.providersData)
  }

  async executeTransaction (options: TransactionOptions = {}): Promise<void> {
    const providerData = this.veramo.providersData[this.provider]
    if (providerData?.rpcUrl === undefined) {
      throw new WalletError('This provider has incomplete information, cannot execute transaction')
    }
    let transaction = options.transaction
    const notifyUser = options.notifyUser ?? true

    if (transaction === undefined) {
      transaction = await this.dialog.text({
        title: 'Execute transaction',
        message: 'Put the transaction. Should start with 0x'
      })
    }
    if (transaction === undefined || !transaction.startsWith('0x')) {
      throw new WalletError(`Invalid transaction ${transaction ?? '<undefined>'}`)
    }

    const notifyUserFn = async (response: ethers.providers.TransactionResponse): Promise<void> => {
      response.wait().then(receipt => {
        this.toast.show({
          message: 'Transaction properly executed',
          type: 'success'
        })
        debug(receipt)
      }).catch(err => {
        const reason: string = err.reason ?? ''
        this.toast.show({
          message: 'Error sending transaction to the ledger' + reason,
          type: 'error'
        })
        debug(reason)
      })
    }

    const sendTransaction = async (provider: ethers.providers.JsonRpcProvider, transaction: string): Promise<void> => {
      const response = await provider.sendTransaction(transaction)
      if (notifyUser) {
        notifyUserFn(response).catch((reason) => {
          debug(reason)
        })
      } else {
        debug(response)
      }
    }

    // Let us shuffle the array of rpcUrls
    const rpcUrls: string[] = shuffleArray((providerData.rpcUrl instanceof Array) ? providerData.rpcUrl : [providerData.rpcUrl])
    const providers = rpcUrls.map(rpcUrl => new ethers.providers.JsonRpcProvider(rpcUrl))

    let success = false
    for (const provider of providers) {
      try {
        await sendTransaction(provider, transaction)
        success = true
        break
      } catch (error) {
        debug(error)
      }
    }

    if (!success) {
      throw new WalletError('Error sending transaction to the blockchain')
    }
  }

  async queryBalance (): Promise<void> {
    const providerData = this.veramo.providersData[this.provider]
    if (providerData?.rpcUrl === undefined) {
      throw new WalletError(`The provider '${this.provider}' has incomplete information: cannot execute transaction`)
    }

    const identities = await this.veramo.agent.didManagerFind()
    const identity = await this.dialog.select({
      message: 'Select an account to get its balance.',
      values: identities,
      getText (identity) {
        return identity.alias ?? identity.did
      }
    })
    if (identity === undefined) {
      throw new WalletError('Query balance cancelled')
    }

    // Let us shuffle the array of rpcUrls
    const rpcUrls: string[] = shuffleArray((providerData.rpcUrl instanceof Array) ? providerData.rpcUrl : [providerData.rpcUrl])
    const providers = rpcUrls.map(rpcUrl => new ethers.providers.StaticJsonRpcProvider(rpcUrl))

    const address = ethers.utils.computeAddress(`0x${identity.keys[0].publicKeyHex}`)
    const balance = await providers[0].getBalance(address)
    console.log(balance)
    const balances = await multipleExecutions({ successRate: 0 }, providers, 'getBalance', address)
    const ether = ethers.utils.formatEther(balances[0])

    this.toast.show({
      message: 'Balance',
      details: `The account '${address}' current balance is ${ether} ETH.`,
      type: 'success'
    })
  }

  async createTransaction (): Promise<void> {
    const providerData = this.veramo.providersData[this.provider]
    if (providerData?.rpcUrl === undefined) {
      throw new WalletError('This provider has incomplete information, cannot execute transaction')
    }

    const identities = await this.veramo.agent.didManagerFind()
    const transactionData = await this.dialog.form<TransactionData>({
      title: 'Create Transaction',
      descriptors: {
        from: {
          type: 'select',
          message: 'Select the origin account',
          values: identities,
          getText (identity) {
            return identity.alias ?? '<UNKNOWN>'
          }
        },
        to: { type: 'text', message: 'Type the destination account' },
        value: { type: 'text', message: 'Put the ether value' },
        sign: { type: 'confirmation', message: 'Sign the transaction?', acceptMsg: 'Sign', rejectMsg: 'Cancel' }
      },
      order: ['from', 'to', 'value', 'sign']
    })
    if (transactionData === undefined) {
      throw new WalletError('Create transaction cancelled')
    }

    // We ask to the fastest RPC endpoint
    const rpcUrls: string[] = shuffleArray((providerData.rpcUrl instanceof Array) ? providerData.rpcUrl : [providerData.rpcUrl])
    const providers = rpcUrls.map(rpcUrl => new ethers.providers.JsonRpcProvider(rpcUrl))

    const from = ethers.utils.computeAddress(`0x${transactionData.from.keys[0].publicKeyHex}`)
    const nonce = (await multipleExecutions({ successRate: 0 }, providers, 'getTransactionCount', from, 'latest'))[0]
    const gasPrice = (await multipleExecutions({ successRate: 0 }, providers, 'getGasPrice'))[0]

    const tx = {
      to: transactionData.to,
      value: ethers.utils.parseEther(transactionData.value),
      nonce: Number(nonce),
      gasLimit: ethers.utils.hexlify(100000),
      gasPrice
    }

    let transaction: string = ''
    if (transactionData.sign) {
      const response = await this.identitySign({ did: transactionData.from.did }, { type: 'Transaction', data: { ...tx, from } })
      transaction = response.signature
    } else {
      transaction = ethers.utils.serializeTransaction(tx)
    }

    await this.dialog.confirmation({
      message: `Transaction created, click the input to copy its value.\n<input value="${transaction}" disabled></input>`,
      acceptMsg: 'Continue',
      rejectMsg: ''
    })
  }

  async wipe (): Promise<void> {
    const confirmation = await this.dialog.confirmation({
      title: 'Delete Wallet?',
      message: 'Are you sure you want to delete this wallet?',
      acceptMsg: 'Delete',
      rejectMsg: 'Cancel'
    })
    if (confirmation !== true) {
      throw new WalletError('Operation rejected by user')
    }

    await Promise.all([
      this.store.clear(),
      this.keyWallet.wipe()
    ])
  }

  // UTILITIES
  async selectIdentity (options?: SelectIdentityOptions): Promise<Identity> {
    const identities = await this.veramo.agent.didManagerFind()
    const message = `${options?.reason ?? 'Authentication required. Please, select an identity to proceed.'}`
    const identity = await this.dialog.select({
      message,
      values: identities,
      getText: (ddo) => ddo.alias !== undefined ? ddo.alias : ddo.did
    })
    if (identity === undefined) {
      throw new WalletError('No did selected')
    }
    return identity
  }

  async selectCredentialsForSdr (sdrMessage: IMessage): Promise<VerifiablePresentation | undefined> {
    if (sdrMessage.data === null || sdrMessage.data === undefined || sdrMessage.from === undefined) {
      return
    }

    const sdrData = sdrMessage.data as SelectiveDisclosureData

    // ** Step 1: Organize the data in an easy to work data structure **

    // Map from DID to its credentials related with this SDR
    const candidateIdentities: CandidateIdentities = {}
    const resources = await this.store.get('resources', {})
    for (const resource of Object.values(resources)) {
      if (resource.type !== 'VerifiableCredential' || resource.identity === undefined) continue

      for (const claim of Object.keys(resource.resource.credentialSubject)) {
        if (claim === 'id') continue

        const requiredClaim = sdrData.claims.find((v) => v.claimType === claim)
        if (requiredClaim !== undefined) {
          let candidateIdentity = candidateIdentities[resource.identity]
          if (candidateIdentity === undefined) {
            candidateIdentity = {}
            candidateIdentities[resource.identity] = candidateIdentity
          }

          let candidateClaim = candidateIdentity[requiredClaim.claimType]
          if (candidateClaim === undefined) {
            candidateClaim = {
              ...requiredClaim,
              credentials: []
            }
            candidateIdentity[requiredClaim.claimType] = candidateClaim
          }

          candidateClaim.credentials.push(resource.resource)
        }
      }
    }

    // ** Step 2: Select the identities that have all the essential claims **

    const validIdentities: CandidateIdentities = {}
    const essentialClaims = sdrData.claims.filter((claim) => claim.essential === true)
    for (const did of Object.keys(candidateIdentities)) {
      const candidateIdentity = candidateIdentities[did]

      // If an identity do no has an essential claim, this identity is marked as invalid
      let valid = true
      for (const essentialClaim of essentialClaims) {
        if (candidateIdentity[essentialClaim.claimType] === undefined) {
          valid = false
          break
        }
      }

      if (valid) {
        validIdentities[did] = candidateIdentity
      }
    }

    // ** Step 3: Select one of the valid identities **

    let selectedDid: string | undefined
    const validDids = Object.keys(validIdentities)
    if (validDids.length === 0) {
      // There is no valid identity. Do no select any
    } else if (validDids.length === 1) {
      // There is only one identity fulfilling the requirement. Use this identity
      selectedDid = Object.keys(validIdentities)[0]
    } else {
      // Select one of the valid identities
      const identities = (await this.veramo.agent.didManagerFind()).filter(identity => validDids.includes(identity.did))
      const message = `Requested claims ${sdrData.claims.map(claim => claim.claimType).join(',')} are available in the following identities. Please select one to continue...`
      const identity = await this.dialog.select({
        message,
        values: identities,
        getText: (identity) => {
          return identity.alias !== undefined ? `${identity.alias} (${displayDid(identity.did)})` : displayDid(identity.did)
        }
      })
      if (identity !== undefined) {
        selectedDid = identity.did
      }
    }

    if (selectedDid === undefined) {
      throw new WalletError('Selective disclousure cancelled by the user', { status: 403 })
    }
    const selectedIdentity = validIdentities[selectedDid]

    // ** Step 4: Execute the selective disclosure **
    const credentials: VerifiableCredential[] = []
    do {
      const disclosure = await this.dialog.form<VerifiableCredentialMap>({
        title: 'Selective disclosure',
        descriptors: Object.values(selectedIdentity).reduce((prev, claim) => {
          const descriptors: DescriptorsMap<VerifiableCredentialMap> = {
            ...prev,
            [claim.claimType]: {
              type: 'select',
              message: `${sdrMessage.from ?? 'UNKNOWN'} has requested the claim <b>${claim.claimType}</b>.You have the following claim/s that meet the request. \nSelect the claim to disclose or leave empty for not disclosing it.${claim.essential === true ? '\n<b>This claim is compulsory. Not disclosing it will cancel the disclosure.</b>' : ''}`,
              values: [undefined, ...claim.credentials],

              getText (credential) {
                if (credential === undefined) {
                  return 'Don\'t disclose'
                }
                const value = credential.credentialSubject[claim.claimType] as string
                return `${claim.claimType}=${value} (by ${displayDid(credential.issuer.id)})`
              },
              getContext (credential) {
                return credential !== undefined ? 'success' : 'danger'
              }
            }
          }

          return descriptors
        }, {}),
        order: Object.keys(selectedIdentity)
      })

      if (disclosure === undefined) {
        const cancel = await this.dialog.confirmation({
          message: 'You cancelled the selective disclosure. Are you sure?',
          acceptMsg: 'Yes',
          rejectMsg: 'No',
          allowCancel: false
        })
        if (cancel === true) {
          throw new WalletError('Selective disclosure denied')
        }
      } else {
        const missingEssentials: string[] = []
        for (const [claimType, credential] of Object.entries(disclosure)) {
          if (credential === undefined) {
            // Check essential credential skipped
            const claim = essentialClaims.find((claim) => claim.claimType === claimType)
            if (claim !== undefined) {
              missingEssentials.push(claimType)
            }
            continue
          }
          credentials.push(credential)
        }

        let continueSelectiveDisclosure: boolean | undefined
        if (missingEssentials.length > 0) {
          continueSelectiveDisclosure = await this.dialog.confirmation({
            message: `You skipped the mandatory claims: ${missingEssentials.join(', ')}. <b>The selective disclosure will be cancelled</b>. \nContinue?`,
            acceptMsg: 'No',
            rejectMsg: 'Yes',
            allowCancel: false
          })
        } else if (credentials.length === 0) {
          continueSelectiveDisclosure = await this.dialog.confirmation({
            message: 'You did not select any claim.<b>The selective disclosure will be cancelled</b>. \nContinue?',
            acceptMsg: 'No',
            rejectMsg: 'Yes',
            allowCancel: false
          })
        } else {
          break
        }

        if (continueSelectiveDisclosure === false) {
          throw new WalletError('Selective disclosure denied')
        }
      }
    } while (true)

    // ** Step 5: Generate Verifiable Presentation **

    const vp = await this.veramo.agent.createVerifiablePresentation({
      presentation: {
        holder: selectedDid,
        verifier: [sdrMessage.from],
        verifiableCredential: credentials,
        request: sdrMessage.raw
      },
      proofFormat: 'jwt',
      save: false
    })

    return vp
  }

  getKeyWallet<T extends KeyWallet> (): T {
    return this.keyWallet as T
  }

  async call (functionMetadata: WalletFunctionMetadata): Promise<void> {
    await (this as any)[functionMetadata.call]()
  }

  // API METHODS

  /**
   * Gets a list of identities managed by this wallet
   * @returns
   */
  async getIdentities (): Promise<BaseWalletModel['identities']> {
    return await this.store.get('identities', {})
  }

  /**
   * Returns a list of DIDs managed by this wallet
   *
   * @param queryParameters. You can filter by alias.
   * @returns
   */
  async identityList (queryParameters: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200> {
    const { alias } = queryParameters
    const identities = await this.veramo.agent.didManagerFind({ alias })
    return identities.map(ddo => ({ did: ddo.did }))
  }

  /**
   * Creates an identity
   * @param requestBody
   * @returns the DID of the created identity
   */
  async identityCreate (requestBody: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201> {
    const { alias } = requestBody
    if (alias !== undefined) {
      const identities = await this.getIdentities()
      for (const identity of Object.values(identities)) {
        if (identity.alias === alias) {
          this.toast.show({
            message: 'Alias already exists',
            details: `An identity with alias ${alias} already exists. If you want to create a new one, please delete the old one first`,
            type: 'warning'
          })
          return { did: identity.did }
        }
      }
    }

    const confirmation = await this.dialog.confirmation({
      message: `Are you sure you want to create an identity${alias !== undefined ? ` with alias '${alias}'` : ''}?`,
      acceptMsg: 'Yes',
      rejectMsg: 'No'
    })
    if (confirmation !== true) {
      throw new WalletError('User cancelled the operation', { status: 403 })
    }

    const { did } = await this.veramo.agent.didManagerCreate({
      alias,
      provider: this.provider
    })
    return { did }
  }

  async identitySelect (queryParameters: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200> {
    const { did } = await this.selectIdentity(queryParameters)
    return { did }
  }

  /**
   * Signs using the identity set in pathParameters. Currently suporting RAW signatures of base64url-encoded data, arbritrary JSON objects (it returns a JWT); and transactions for the DLT.
   * @param pathParameters
   * @param requestBody
   * @returns
   */
  async identitySign (pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200> {
    let response: WalletPaths.IdentitySign.Responses.$200
    switch (requestBody.type) {
      case 'Transaction': {
        const { data: transaction } = requestBody
        if (transaction === undefined) {
          throw new WalletError('No transaction present on the request', { code: 400 })
        }
        const identity = await this.veramo.agent.didManagerGet(pathParameters)
        const signature = await this.veramo.agent.keyManagerSignEthTX({
          kid: identity.keys[0].kid,
          transaction
        })
        response = { signature }
        break
      }
      case 'Raw': {
        const { data } = requestBody
        if (data === undefined) {
          throw new WalletError('No data present on the request', { code: 400 })
        }
        const identity = await this.veramo.agent.didManagerGet(pathParameters)
        const signature = await this.veramo.agent.keyManagerSignJWT({
          kid: identity.keys[0].kid,
          data: u8a.fromString(data.payload, 'base64url')
        })
        response = { signature }
        break
      }
      case 'JWT': {
        const { data } = requestBody
        if (data === undefined) {
          throw new WalletError('No data present on the request', { code: 400 })
        }
        const identity = await this.veramo.agent.didManagerGet(pathParameters)
        const header = {
          ...(data.header as object) ?? undefined,
          alg: 'ES256K',
          typ: 'JWT'
        }
        const payload = {
          ...(data.payload as object),
          iss: pathParameters.did,
          iat: Math.floor(Date.now() / 1000)
        }
        const jwsDataToSign = jwsSignInput(header, payload)
        const signature = await this.veramo.agent.keyManagerSignJWT({
          kid: identity.keys[0].kid,
          data: jwsDataToSign
        })
        response = { signature: `${jwsDataToSign}.${signature}` }
        break
      }
      default:
        throw new WalletError('Unknown sign data type')
    }

    return response
  }

  /**
   * Returns info regarding an identity. It includes DLT addresses bounded to the identity
   *
   * @param pathParameters
   * @returns
   */
  async identityInfo (pathParameters: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200> {
    const ddo = await this.veramo.agent.didManagerGet({
      did: pathParameters.did
    })
    const result = _.pick(ddo, ['did', 'alias', 'provider'])
    let addresses: string[] = []
    if (ddo.provider.startsWith('did:ethr')) {
      addresses = ddo.keys.map((key) => ethers.utils.computeAddress(`0x${key.publicKeyHex}`))
    }

    return { ...result, addresses }
  }

  async identityDeployTransaction (pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletComponents.Schemas.Transaction): Promise<WalletComponents.Schemas.Receipt> {
    throw new Error('Method not implemented.')
  }

  /**
   * Get resources stored in the wallet's vault. It is the place where to find stored verfiable credentials, agreements, non-repudiable proofs.
   * @returns
   */
  async getResources (): Promise<ResourceMap> {
    return await this.store.get('resources', {})
  }

  private async getResource (id?: keyof BaseWalletModel['resources']): Promise<Resource> {
    const resourcesMap = await this.getResources()
    const resources = Object
      .keys(resourcesMap)
      .map(key => resourcesMap[key])
      .filter((resource) => resource.id === id)

    if (resources.length !== 1) {
      throw Error('resource not found')
    }
    return resources[0]
  }

  private async setResource (resource: Resource): Promise<void> {
    // If a parentResource is provided, do not allow to store the resource if it does not exist
    let parentResource: Resource | undefined
    if (resource.parentResource !== undefined) {
      try {
        parentResource = await this.getResource(resource.parentResource)
      } catch (error) {
        debug('Failed to add resource since parent resource does not exist:\n' + JSON.stringify(resource, undefined, 2))
        throw new Error('Parent resource for provided resource does not exist')
      }
    }

    // If an identity is provided, do not allow to store the resource if it does not exist.
    if (resource.identity !== undefined) {
      if (!await this.store.has(`identities.${resource.identity}`)) {
        debug('Failed to add resource since the identity is associated to does not exist:\n' + JSON.stringify(resource, undefined, 2))
        throw new Error('Identity for this resource does not exist')
      }
    }

    if (parentResource !== undefined) {
      // Do not allow as well a children resource with a different identity than its father
      if (resource.identity !== undefined && parentResource.identity !== resource.identity) {
        debug('Failed to add resource since it has a different identity than its parent resource')
        throw new Error('Identity mismatch between parent and child resources')
      }
      // If child identity is not provided, it inherits its parent's
      if (resource.identity === undefined) {
        resource.identity = parentResource.identity
      }
    }

    await this.store.set(`resources.${resource.id}`, resource)
  }

  /**
   * Gets a list of resources stored in the wallet's vault.
   * @returns
   */
  async resourceList (query: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200> {
    const queries = Object.keys(query) as Array<keyof (typeof query)>
    const extraConsent: string[] = []
    const filters: Array<(resource: Resource) => boolean> = []

    if (queries.includes('type')) {
      extraConsent.push(`type '<code>${query.type ?? 'unknown'}</code>'`)
      filters.push((resource) => resource.type === query.type)
    }
    if (queries.includes('identity')) {
      if (query.identity !== '' && query.identity !== undefined) {
        extraConsent.push(`identity '<code>${query.identity}</code>'`)
        filters.push((resource) => resource.identity === query.identity)
      } else {
        extraConsent.push('not liked to any identity')
        filters.push((resource) => resource.identity === undefined)
      }
    }
    if (queries.includes('parentResource')) {
      let parentResource: Resource
      try {
        parentResource = await this.getResource(query.parentResource)
      } catch (error) {
        throw new WalletError('Invalid parentResource id', { status: 400 })
      }
      if (query.parentResource !== '' && query.parentResource !== undefined) {
        extraConsent.push(`parent-resource:\n\tid '<code>${query.parentResource}</code>\n\t<code>${parentResource.type}</code>'`)
        filters.push((resource) => resource.parentResource === query.parentResource)
      } else {
        filters.push((resource) => resource.parentResource === undefined)
      }
    }

    // TODO: Use wallet-protocol token to get the application name
    const consentText = `One application wants to retrieve all your stored resources${extraConsent.length > 0 ? ' with:\n' + extraConsent.join('\n\t') : ''}.\nDo you agree?`
    const confirmation = await this.dialog.confirmation({
      message: consentText,
      acceptMsg: 'Yes',
      rejectMsg: 'No'
    })
    if (confirmation === false) {
      throw new WalletError('User cancelled the operation', { status: 403 })
    }

    const resourcesMap = await this.getResources()
    const resources = Object
      .keys(resourcesMap)
      .map(key => resourcesMap[key])
      .filter((resource) => filters.reduce((success, filter) => success && filter(resource), true))

    return resources
  }

  /**
   * Deletes a given resource and all its children
   * @param id
   */
  async deleteResource (id: string, requestConfirmation = true): Promise<void> {
    let confirmation: boolean | undefined = true
    if (requestConfirmation) {
      confirmation = await this.dialog.confirmation({
        message: 'Are you sure you want to delete this resource and all its children resources (if any)? This action cannot be undone',
        acceptMsg: 'Delete',
        rejectMsg: 'Cancel'
      })
    }
    if (confirmation === true) {
      await this.store.delete(`resources.${id}`)
      const resourcesMap = await this.getResources()
      const resources = Object
        .keys(resourcesMap)
        .map(key => resourcesMap[key])
        .filter((resource) => resource.parentResource === id)
      for (const resource of resources) {
        await this.deleteResource(resource.id, false)
      }
    }
  }

  /**
   * Deletes a given identity (DID) and all its associated resources
   * @param did
   */
  async deleteIdentity (did: string): Promise<void> {
    const confirmation = await this.dialog.confirmation({
      message: 'Are you sure you want to delete this identity and all its associated resources (if any)?\n' + did + '\nThis action cannot be undone',
      acceptMsg: 'Delete',
      rejectMsg: 'Cancel'
    })
    if (confirmation === true) {
      await this.veramo.agent.didManagerDelete({ did })
      const resourcesMap = await this.getResources()
      const resources = Object
        .keys(resourcesMap)
        .map(key => resourcesMap[key])
        .filter((resource) => resource.identity === did)
      for (const resource of resources) {
        await this.deleteResource(resource.id, false)
      }
    }
  }

  /**
   * Securely stores in the wallet a new resource.
   *
   * @param requestBody
   * @returns and identifier of the created resource
   */
  async resourceCreate (requestBody: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201> {
    const resource: Resource = { ...requestBody, id: uuid() }

    // Very hacky but it is the only place. If the resource is a contract without a keypair, we look for an existing one and we add it
    if (resource.type === 'Contract' && resource.resource.keyPair === undefined) {
      // A contract parent resource is a keyPair
      let parentId: string | undefined
      let keyPairResource: KeyPairResource
      try {
        parentId = await digest(resource.resource.dataSharingAgreement.dataExchangeAgreement.orig)
        keyPairResource = (await this.getResource(parentId)) as KeyPairResource
      } catch (error) {
        try {
          parentId = await digest(resource.resource.dataSharingAgreement.dataExchangeAgreement.dest)
          keyPairResource = (await this.getResource(parentId)) as KeyPairResource
        } catch (error2) {
          throw new WalletError('No associated keyPair found for this contract, please provide one', { status: 400 })
        }
      }
      resource.resource.keyPair = keyPairResource.resource.keyPair
      resource.parentResource = parentId
    }

    // Validate resource
    const validation = await this.resourceValidator.validate(resource, this.veramo)
    if (!validation.validated) {
      throw new WalletError(`Resource validation failed: type ${resource.type} not supported`, { status: 400 })
    }

    if (validation.errors.length > 0) {
      const errorMsg: string[] = []
      validation.errors.forEach((error) => {
        errorMsg.push(error.message)
      })
      throw new WalletError('Resource validation failed:\n' + errorMsg.join('\n'), { status: 400 })
    }

    switch (resource.type) {
      case 'VerifiableCredential': {
        const credentialSubject = getCredentialClaims(resource.resource)
          .map(claim => `  - ${claim}: ${JSON.stringify(resource.resource.credentialSubject[claim])}`)
          .join('\n')
        const confirmation = await this.dialog.confirmation({
          message: `Do you want to add the following verifiable credential: \n${credentialSubject}`
        })
        if (confirmation !== true) {
          throw new WalletError('User cancelled the operation', { status: 403 })
        }
        break
      }
      case 'Object': {
        const confirmation = await this.dialog.confirmation({
          message: 'Do you want to add an object into your wallet?'
        })
        if (confirmation !== true) {
          throw new WalletError('User cancelled the operation', { status: 403 })
        }
        break
      }
      case 'KeyPair': {
        const confirmation = await this.dialog.confirmation({
          message: `Do you want to add the following keys to your wallet?\n\t${JSON.stringify(resource.resource.keyPair, undefined, 2)}`
        })
        if (confirmation !== true) {
          throw new WalletError('User cancelled the operation', { status: 403 })
        }
        break
      }
      case 'Contract': {
        const { dataSharingAgreement, keyPair } = resource.resource // They keyPair is assigned before validation, so it cannot be undefined
        const confirmation = await this.dialog.confirmation({
          message: `Do you want to add a data-sharing agreement to your wallet?\n\tofferingId: ${dataSharingAgreement.dataOfferingDescription.dataOfferingId}\n\tproviderDID: ${dataSharingAgreement.parties.providerDid}\n\tconsumerDID: ${dataSharingAgreement.parties.consumerDid}`
        })
        if (confirmation !== true) {
          throw new WalletError('User cancelled the operation', { status: 403 })
        }

        const parentId = await digest(keyPair!.publicJwk)
        // If the keyPair was already created, we overwrite it
        const keyPairResource: KeyPairResource = {
          id: parentId,
          identity: resource.identity, // If the contract sets an identity, the keypair will be assigned to that identity as well
          type: 'KeyPair',
          resource: { keyPair: keyPair! }
        }
        // A contract parent resource is a keyPair
        resource.parentResource = parentId

        try {
          await this.setResource(keyPairResource)
        } catch (error) {
          throw new WalletError('Failed to add resource', { status: 500 })
        }

        break
      }
      case 'NonRepudiationProof': {
        const decodedProof: NrProofPayload = decodeJWS(resource.resource).payload

        const dataExchange = decodedProof.exchange
        const { id, cipherblockDgst, blockCommitment, secretCommitment, ...dataExchangeAgreement } = dataExchange
        const parentId = await digest(dataExchangeAgreement)

        const alreadyConfirmed = this.confirmations[parentId]

        if (!alreadyConfirmed) {
          const yes = { value: 'yes', text: 'Yes', context: 'success' as DialogOptionContext }
          const no = { value: 'no', text: 'No', context: 'danger' as DialogOptionContext }
          const yesToAll = { value: 'yesToAll', text: 'Yes to all for this data sharing agreement', context: 'success' as DialogOptionContext }
          const confirmation = await this.dialog.select({
            message: `Do you want to add a non-repudiation proof into your wallet?\nType: ${decodedProof.proofType}\nExchangeId: ${await exchangeId(decodedProof.exchange)}`,
            values: [yes, yesToAll, no],
            getText: (option) => option.text,
            getContext: (option) => option.context,
            showInput: false
          })

          if (confirmation === undefined || confirmation.value === 'no') {
            throw new WalletError('User cancelled the operation', { status: 403 })
          }

          if (confirmation.value === 'yesToAll') {
            this.confirmations[parentId] = true
          }
        }

        // If the data exchange has not been yet created, add it to the resources
        if (!await this.store.has(`resources.${resource.parentResource as string}`)) {
          const dataExchangeResource: DataExchangeResource = {
            id,
            parentResource: parentId,
            type: 'DataExchange',
            resource: dataExchange
          }
          try {
            await this.setResource(dataExchangeResource)
          } catch (error) {
            throw new WalletError('Failed to add resource', { status: 500 })
          }
        }
        break
      }

      default:
        throw new WalletError('Resource type not supported', { status: 501 })
    }

    await this.setResource(resource)

    return resource
  }

  /**
   * Initiates the flow of choosing which credentials to present after a selective disclosure request.
   * @param pathParameters
   * @returns
   */
  async selectiveDisclosure (pathParameters: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200> {
    const sdrRaw = pathParameters.jwt
    let sdrMessage
    try {
      sdrMessage = await this.veramo.agent.handleMessage({
        raw: sdrRaw,
        save: false
      })
    } catch (err: unknown) {
      if (err instanceof Error) {
        throw new WalletError(`Cannot verify selective disclousure request: ${err.message}`)
      }
      throw err
    }

    if (sdrMessage.from === undefined) {
      throw new WalletError('Selective disclosure request origin not defined')
    }

    const vp = await this.selectCredentialsForSdr(sdrMessage)
    if (vp === undefined) {
      throw new WalletError('No verifiable credentials selected')
    }

    return {
      jwt: vp.proof.jwt
    }
  }

  /**
   * Deploys a transaction to the connected DLT
   * @param requestBody
   * @returns
   */
  async transactionDeploy (requestBody: WalletComponents.Schemas.SignedTransaction): Promise<WalletPaths.TransactionDeploy.Responses.$200> {
    await this.executeTransaction({
      transaction: requestBody.transaction
    })
    return {}
  }

  /**
   * Verifies a JWT resolving the public key from the signer DID (no other kind of signer supported) and optionally check values for expected payload claims.
   *
   * The Wallet only supports the 'ES256K1' algorithm.
   *
   * Useful to verify JWT created by another wallet instance.
   * @param requestBody
   * @returns
   */
  async didJwtVerify (requestBody: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200> {
    try {
      return await didJwtVerifyFn(requestBody.jwt, this.veramo, requestBody.expectedPayloadClaims)
    } catch (error) {
      if (typeof error === 'string') { throw new WalletError(error) }
      throw new Error(typeof error === 'string' ? error : 'unknown error')
    }
  }

  /**
   * Retrieves information regarding the current connection to the DLT.
   * @returns
   */
  async providerinfoGet (): Promise<WalletPaths.ProviderinfoGet.Responses.$200> {
    const providerData = this.veramo.providersData[this.provider]
    return {
      provider: this.provider,
      ...providerData
    }
  }
}
