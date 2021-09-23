import { WalletComponents, WalletPaths } from '@i3-market/wallet-desktop-openapi/types'
import _ from 'lodash'
import { IMessage, VerifiableCredential, VerifiablePresentation } from '@veramo/core'
import { v4 as uuid } from 'uuid'

import { base64url, getCredentialClaims, jwkSecret } from '../utils'

import { BaseWalletModel, DescriptorsMap, Dialog, Identity, Store } from '../app'
import { KeyWallet } from '../keywallet'
import { ResourceValidator } from '../resource'
import Veramo from '../veramo'
import { WalletError } from '../errors'

import { Wallet } from './wallet'
import { WalletOptions } from './wallet-options'
import { displayDid } from '../utils/display-did'
import { DEFAULT_PROVIDER } from '../veramo/veramo'

type Account = WalletComponents.Schemas.Account

interface WalletOptionsCryptoWallet {
  keyWallet: KeyWallet
}

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

export class BaseWallet<
  Options extends WalletOptions<Model> & WalletOptionsCryptoWallet,
  Model extends BaseWalletModel = BaseWalletModel
> implements Wallet {
  public dialog: Dialog
  public store: Store<Model>
  public veramo: Veramo<Model>

  protected keyWallet: KeyWallet
  protected resourceValidator: ResourceValidator
  protected provider: string

  constructor (opts: Options) {
    this.dialog = opts.dialog
    this.store = opts.store
    this.keyWallet = opts.keyWallet
    this.resourceValidator = new ResourceValidator()
    this.provider = opts.provider ?? DEFAULT_PROVIDER

    // Init veramo framework
    this.veramo = new Veramo(this.store, this.keyWallet)
  }

  prepareForJWSSigning (messageToSign: any): any {

  }

  async wipe (): Promise<void> {
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
      throw new WalletError('Selective disclousure cancelled by the user')
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
              message: `${sdrMessage.from ?? 'UNKNOWN'} has requested the claim <b>${claim.claimType}</b>.You have the following claim/s that meet the request. \nSelect the claim to disclouse or leave empty for not disclousing it.${claim.essential === true ? '\n<b>This claim is compulsory. Not disclosing it will cancel the disclosure.</b>' : ''}`,
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
            message: `You skipped the mandatory claims: ${missingEssentials.join(', ')}. <b>The selective disclosure will be canceled</b>. \nContinue?`,
            acceptMsg: 'No',
            rejectMsg: 'Yes',
            allowCancel: false
          })
        } else if (credentials.length === 0) {
          continueSelectiveDisclosure = await this.dialog.confirmation({
            message: 'You did not select any claim.<b>The selective disclosure will be canceled</b>. \nContinue?',
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

  // Wallet interface abstract methods
  async accountList (query: WalletPaths.AccountList.QueryParameters): Promise<WalletPaths.AccountList.Responses.$200> {
    const accounts = await this.store.get('accounts', {})

    // Filter params
    // TO-DO: Add a list of protected properties tha SHOULD not be exported, e.g. "key"
    return Object.keys(accounts).map(accountId => {
      const account = accounts[accountId]
      const filteredAccount = _.pick(account, _.defaults(query.props)) as Account
      return filteredAccount
    }).filter((account) => Object.keys(account).length !== 0)
  }

  async accountCreate (requestBody: WalletPaths.AccountCreate.RequestBody): Promise<WalletPaths.AccountCreate.Responses.$201> {
    const account: Account = {
      id: '',
      ...requestBody
    }
    account.type = account.type ?? 'Identity'

    if (account.type === 'Identity') {
      account.id = await this.keyWallet.createAccountKeyPair()
    } else {
      const secret = jwkSecret()
      account.id = secret.kid
      account.key = secret
    }

    await this.store.set(`accounts.${account.id}`, account)
    return {
      id: account.id,
      type: account.type
    }
  }

  /**
   *
   * @todo JWS Support
   * @todo Secret type signing
   *
   * @param requestBody
   * @returns a base64url-encoded string of the signature or a JWS (if signing of an object is requested)
   */
  async accountSign (requestBody: WalletPaths.AccountSign.RequestBody): Promise<WalletPaths.AccountSign.Responses.$200> {
    let buffer: Buffer
    try {
      if (typeof requestBody.messageToSign === 'string') {
        buffer = base64url.decode(requestBody.messageToSign)
      } else {
        const jws = this.prepareForJWSSigning(requestBody.messageToSign)
        buffer = Buffer.from(jws)
      }
    } catch (error) {
      console.error('Message should be a valid base64url string or a plain JS object')
      throw error
    }

    let accountId = requestBody.accountId
    if (accountId === undefined) {
      const account = await (this.dialog as any).selectAccount({
        message: 'Select an account',
        timeout: 20
      })
      if (account === undefined) {
        throw new Error('The user did not select any account')
      }

      accountId = account.id
    }

    const signature = await this.keyWallet.signDigest(accountId as any, buffer)
    return base64url.encode(Buffer.from(signature))
  }

  async accountVerify (requestBody: WalletPaths.AccountVerify.RequestBody): Promise<WalletPaths.AccountVerify.Responses.$200> {
    throw new Error('Not implemented yet')
  }

  async accountEncrypt (requestBody: WalletPaths.AccountEncrypt.RequestBody): Promise<WalletPaths.AccountEncrypt.Responses.$200> {
    throw new Error('Not implemented yet')
  }

  async accountDecrypt (requestBody: WalletPaths.AccountDecrypt.RequestBody): Promise<WalletPaths.AccountDecrypt.Responses.$200> {
    throw new Error('Not implemented yet')
  }

  async getIdentities (): Promise<BaseWalletModel['identities']> {
    return await this.store.get('identities', {})
  }

  async identityList (queryParameters: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200> {
    const { alias } = queryParameters
    const identities = await this.veramo.agent.didManagerFind({ alias })
    return identities.map(ddo => ({ did: ddo.did }))
  }

  async identityCreate (requestBody: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201> {
    const { alias } = requestBody
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

  async getResources (): Promise<BaseWalletModel['resources']> {
    return await this.store.get('resources', {})
  }

  async resourceList (): Promise<WalletPaths.ResourceList.Responses.$200> {
    const resources = await this.getResources()
    return Object.keys(resources).map(key => ({
      id: resources[key].id
    }))
  }

  async resourceCreate (requestBody: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201> {
    const resource = requestBody

    // Validate resource
    const validation = await this.resourceValidator.validate(resource, this.veramo)
    if (!validation.validated) {
      throw new Error(`Resource type ${resource.type} not supported`)
    }

    if (validation.errors.length > 0) {
      throw new WalletError('Wrong resource format', { status: 400 })
    }

    if (resource.type === 'VerifiableCredential') {
      const credentialSubject = getCredentialClaims(resource.resource)
        .map(claim => `  - ${claim}: ${JSON.stringify(resource.resource.credentialSubject[claim])}`)
        .join('\n')
      const confirmation = await this.dialog.confirmation({
        message: `Do you want to add the following verifiable credential: \n${credentialSubject}`
      })
      if (confirmation !== true) {
        throw new WalletError('User cannceled the operation', { status: 403 })
      }
    }

    // Store resource
    const resourceId = {
      id: uuid()
    }
    const returnResource = Object.assign(resource, resourceId)
    await this.store.set(`resources.${resourceId.id}`, returnResource)
    return resourceId
  }

  async selectiveDisclosure (pathParameters: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200> {
    const sdrRaw = pathParameters.jwt
    const sdrMessage = await this.veramo.agent.handleMessage({
      raw: sdrRaw,
      save: false
    })

    if (sdrMessage.from === undefined) {
      throw new WalletError('Selective disclosure request origin not defined')
    }

    // TODO: Add user consent
    const vp = await this.selectCredentialsForSdr(sdrMessage)
    if (vp === undefined) {
      throw new WalletError('No verifiable credentials selected')
    }

    return {
      jwt: vp.proof.jwt
    }
  }
}
