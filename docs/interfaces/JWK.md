# Interface: JWK

## Hierarchy

- `JWK`

  ↳ **`JWK`**

## Table of contents

### Properties

- [alg](JWK.md#alg)
- [crv](JWK.md#crv)
- [d](JWK.md#d)
- [dp](JWK.md#dp)
- [dq](JWK.md#dq)
- [e](JWK.md#e)
- [ext](JWK.md#ext)
- [k](JWK.md#k)
- [key\_ops](JWK.md#key_ops)
- [kid](JWK.md#kid)
- [kty](JWK.md#kty)
- [n](JWK.md#n)
- [oth](JWK.md#oth)
- [p](JWK.md#p)
- [q](JWK.md#q)
- [qi](JWK.md#qi)
- [use](JWK.md#use)
- [x](JWK.md#x)
- [x5c](JWK.md#x5c)
- [x5t](JWK.md#x5t)
- [x5t#S256](JWK.md#x5t#s256)
- [x5u](JWK.md#x5u)
- [y](JWK.md#y)

## Properties

### alg

• **alg**: ``"ES256"`` \| ``"ES384"`` \| ``"ES512"`` \| ``"A128GCM"`` \| ``"A256GCM"``

#### Overrides

JWKjose.alg

#### Defined in

[src/ts/types.ts:24](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/9896c06/src/ts/types.ts#L24)

___

### crv

• `Optional` **crv**: `string`

#### Inherited from

JWKjose.crv

#### Defined in

node_modules/jose/dist/types/types.d.ts:100

___

### d

• `Optional` **d**: `string`

#### Inherited from

JWKjose.d

#### Defined in

node_modules/jose/dist/types/types.d.ts:101

___

### dp

• `Optional` **dp**: `string`

#### Inherited from

JWKjose.dp

#### Defined in

node_modules/jose/dist/types/types.d.ts:102

___

### dq

• `Optional` **dq**: `string`

#### Inherited from

JWKjose.dq

#### Defined in

node_modules/jose/dist/types/types.d.ts:103

___

### e

• `Optional` **e**: `string`

#### Inherited from

JWKjose.e

#### Defined in

node_modules/jose/dist/types/types.d.ts:104

___

### ext

• `Optional` **ext**: `boolean`

JWK "ext" (Extractable) Parameter.

#### Inherited from

JWKjose.ext

#### Defined in

node_modules/jose/dist/types/types.d.ts:106

___

### k

• `Optional` **k**: `string`

#### Inherited from

JWKjose.k

#### Defined in

node_modules/jose/dist/types/types.d.ts:107

___

### key\_ops

• `Optional` **key\_ops**: `string`[]

JWK "key_ops" (Key Operations) Parameter.

#### Inherited from

JWKjose.key\_ops

#### Defined in

node_modules/jose/dist/types/types.d.ts:109

___

### kid

• `Optional` **kid**: `string`

JWK "kid" (Key ID) Parameter.

#### Inherited from

JWKjose.kid

#### Defined in

node_modules/jose/dist/types/types.d.ts:111

___

### kty

• `Optional` **kty**: `string`

JWK "kty" (Key Type) Parameter.

#### Inherited from

JWKjose.kty

#### Defined in

node_modules/jose/dist/types/types.d.ts:113

___

### n

• `Optional` **n**: `string`

#### Inherited from

JWKjose.n

#### Defined in

node_modules/jose/dist/types/types.d.ts:114

___

### oth

• `Optional` **oth**: { `d?`: `string` ; `r?`: `string` ; `t?`: `string`  }[]

#### Inherited from

JWKjose.oth

#### Defined in

node_modules/jose/dist/types/types.d.ts:115

___

### p

• `Optional` **p**: `string`

#### Inherited from

JWKjose.p

#### Defined in

node_modules/jose/dist/types/types.d.ts:120

___

### q

• `Optional` **q**: `string`

#### Inherited from

JWKjose.q

#### Defined in

node_modules/jose/dist/types/types.d.ts:121

___

### qi

• `Optional` **qi**: `string`

#### Inherited from

JWKjose.qi

#### Defined in

node_modules/jose/dist/types/types.d.ts:122

___

### use

• `Optional` **use**: `string`

JWK "use" (Public Key Use) Parameter.

#### Inherited from

JWKjose.use

#### Defined in

node_modules/jose/dist/types/types.d.ts:124

___

### x

• `Optional` **x**: `string`

#### Inherited from

JWKjose.x

#### Defined in

node_modules/jose/dist/types/types.d.ts:125

___

### x5c

• `Optional` **x5c**: `string`[]

JWK "x5c" (X.509 Certificate Chain) Parameter.

#### Inherited from

JWKjose.x5c

#### Defined in

node_modules/jose/dist/types/types.d.ts:128

___

### x5t

• `Optional` **x5t**: `string`

JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter.

#### Inherited from

JWKjose.x5t

#### Defined in

node_modules/jose/dist/types/types.d.ts:130

___

### x5t#S256

• `Optional` **x5t#S256**: `string`

"x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter.

#### Inherited from

JWKjose.x5t#S256

#### Defined in

node_modules/jose/dist/types/types.d.ts:132

___

### x5u

• `Optional` **x5u**: `string`

JWK "x5u" (X.509 URL) Parameter.

#### Inherited from

JWKjose.x5u

#### Defined in

node_modules/jose/dist/types/types.d.ts:134

___

### y

• `Optional` **y**: `string`

#### Inherited from

JWKjose.y

#### Defined in

node_modules/jose/dist/types/types.d.ts:126
