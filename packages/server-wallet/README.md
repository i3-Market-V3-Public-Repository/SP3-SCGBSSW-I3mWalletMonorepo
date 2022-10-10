# @i3m/server-wallet

Get a ready-to-go Wallet requiring no user interaction and using a simple file to store wallet data. It should be used only when no human interaction is possible.

## Install

```console
npm install @i3m/server-wallet
```

## Use

The server wallet uses a file as storage, Optional `filepath` is the path to the Wallet's storage file. If you are using a container it should be a path to a file that persists (like one in a volume)

The wallet's storage-file can be encrypted for added security by passing an optional `password`.

Example of instantiation of a server wallet in typescript:

```typescript
wallet = await serverWalletBuilder({ password: '1735b07cb074bc1057vc130377$(==)(5v0bx23YGSA', filepath: '/path/where/the/wallet/will/store/things' })
```

## Create an identity (DID)

```typescript
const resp = await wallet.identityCreate({
  alias: 'identity1'
})
console.log(`DID for identity1 created: `, resp.did)
```

## List identities

```typescript
const identities = await wallet.identityList({})
console.log('Identities: ', identities)
```

## Generate a signet JWT

You can generate a signature as a JWT for a generic JSON object as, for instance:

```typescript
const objectToSign = {
  field1: 'yellow',
  field2: 'brown'
}
jwt = (await wallet.identitySign({ did: 'one of the dids in the wallet' }, { type: 'JWT', data: { payload: objectToSign } })).signature
```

## Verify a signed JWT

You can also use your wallet to verify a JWT signed by other wallets as:

```typescript
const verification = await wallet.didJwtVerify({ jwt })
if (verification.verification === 'success') {
  // properly verified
} else {
  // failed with error msg in verification.error
}
```

The verification can also check for specific payload claims. An expected value of '' can be used to just check that the claim is in the payload.

```typescript
const verification = await wallet.didJwtVerify({
  jwt,
  expectedPayloadClaims: {
    field1: 'yellow'  // check that "field1"="yellow" is in the JWT payload
    field2: '' // check that "field2" is defined in the JWT payload
  }
})
if (verification.verification === 'success') {
  // properly verified
} else {
  // failed with error msg in verification.error
}
```
