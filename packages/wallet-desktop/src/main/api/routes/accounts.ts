import crypto from 'crypto'
import { RequestHandler } from 'express'
import { generateKeyPair } from 'jose/util/generate_key_pair'
import { generateSecret } from 'jose/util/generate_secret'
import fromKeyLike from 'jose/jwk/from_key_like'
import { parseJwk } from 'jose/jwk/parse'
import { v4 as uuidv4 } from 'uuid'
import keytar from 'keytar'
import _ from 'lodash'
import { WalletComponents, WalletPaths } from '@i3-market/wallet-desktop-openapi/types'

import { extractLocals, WindowManager } from '@wallet/main/internal'

type Modify<T, R> = Omit<T, keyof R> & R

type AccountListInputDefaults = Modify<WalletComponents.Schemas.AccountListInput, {
  props: string[]
}>

export const accountList: RequestHandler<{}, WalletPaths.AccountList.Responses.$200, WalletPaths.AccountList.QueryParameters, AccountListInputDefaults> = async (req, res) => {
  const { windowManager } = extractLocals(req.app)
  windowManager.openSignWindow('accountList')

  const accounts: WalletPaths.AccountList.Responses.$200 = []
  const accountList = await keytar.findCredentials('simple-wallet')

  // Process parameters
  const requestPublicKey = (req.query.props !== undefined) ? req.query.props.filter((keys) => keys.startsWith('publicKey')).length > 0 : false
  for (const keytarAccount of accountList) {
    // Get account from keytar password
    const account: WalletComponents.Schemas.Account = JSON.parse(keytarAccount.password)

    if (req.query.account_ids !== undefined && !req.query.account_ids.includes(account.id)) continue

    if (account.type === 'Identity' && account.key !== undefined) {
      // Obtain public key using private key
      if (account.publicKey === undefined && requestPublicKey) {
        const privateKey = await parseJwk(account.key)
        const publicKey = crypto.createPublicKey(privateKey as crypto.KeyObject)
        const publicJwk = await fromKeyLike(publicKey)
        account.publicKey = publicJwk
      }
    }

    // Filter params
    const filteredAccount = _.pick(account, _.defaults(req.query.props))
    if (Object.keys(filteredAccount).length > 0) {
      accounts.push(filteredAccount as WalletComponents.Schemas.Account)
    }
  }

  res.json(accounts)
}

export const accountCreate: RequestHandler<{}, WalletPaths.AccountCreate.Responses.$201, WalletPaths.AccountCreate.RequestBody, any> = async (req, res) => {
  const { windowManager } = extractLocals(req.app)
  windowManager.openSignWindow('accountCreate')

  const type: WalletComponents.Schemas.AccountType = req.body.type
  const kid = uuidv4()

  const alg = (type === 'Secret')
    ? 'HS256'
    : 'ES256'

  const key = (type === 'Secret')
    ? await generateSecret(alg)
    : (await generateKeyPair(alg)).privateKey

  const jwk = (await fromKeyLike(key))
  jwk.kid = kid
  jwk.alg = alg

  if (type === 'Secret') {
    jwk.key_ops = ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits']
  } else {
    jwk.key_ops = ['sign', 'verify']
    jwk.use = 'sig'
  }

  const account = _accountCreate(type, jwk, req.body.name ?? kid, req.body.comment)

  await keytar.setPassword('simple-wallet', account.id, JSON.stringify(account))

  windowManager.openSignWindow(`Created account ${kid}`)

  const response = {
    type,
    id: account.id
  }

  res.status(201).send(response)
}

export const accountEncrypt: RequestHandler<{}, WalletPaths.AccountEncrypt.Responses.$200, WalletPaths.AccountEncrypt.RequestBody> = (req, res) => {
  const windowManager: WindowManager = req.app.locals.windowManager
  windowManager.openSignWindow('hello')
  console.log('Hello world')
  const jwe = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: {
      jku: 'https://server.example.com/keys.jwks'
    },
    header: {
      alg: 'A128KW',
      kid: '7'
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw'
  }
  res.json(jwe)
}

export const accountDecrypt: RequestHandler<{}, WalletPaths.AccountDecrypt.Responses.$200, WalletPaths.AccountDecrypt.RequestBody> = (req, res) => {
  const windowManager: WindowManager = req.app.locals.windowManager
  windowManager.openSignWindow('hello')
  console.log('Hello world')
  res.send('Hello world')
}

export const accountSign: RequestHandler<{}, WalletPaths.AccountSign.Responses.$200, WalletPaths.AccountSign.RequestBody> = (req, res) => {
  const windowManager: WindowManager = req.app.locals.windowManager
  windowManager.openSignWindow('hello')
  console.log('Hello world')
  res.send('Hello world')
}

export const accountVerify: RequestHandler<{}, WalletPaths.AccountVerify.Responses.$200, WalletPaths.AccountVerify.RequestBody> = (req, res) => {
  const windowManager: WindowManager = req.app.locals.windowManager
  windowManager.openSignWindow('hello')
  console.log('Hello world')
  res.send({ verified: false })
}

function _accountCreate (type: WalletComponents.Schemas.AccountType, key: WalletComponents.Schemas.JWK, name: string, description?: string): WalletComponents.Schemas.Account {
  if (key.kid === undefined) {
    key.kid = uuidv4()
  }
  return {
    id: key.kid,
    name,
    type,
    key,
    description
  }
}
