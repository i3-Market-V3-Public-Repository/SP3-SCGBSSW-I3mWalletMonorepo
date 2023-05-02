# Class: MasterKey

## Table of contents

### Constructors

- [constructor](MasterKey.md#constructor)

### Properties

- [cipher](MasterKey.md#cipher)
- [decipher](MasterKey.md#decipher)
- [from](MasterKey.md#from)
- [na](MasterKey.md#na)
- [nb](MasterKey.md#nb)
- [port](MasterKey.md#port)
- [secret](MasterKey.md#secret)
- [to](MasterKey.md#to)

### Methods

- [decrypt](MasterKey.md#decrypt)
- [encrypt](MasterKey.md#encrypt)
- [fromHash](MasterKey.md#fromhash)
- [toHash](MasterKey.md#tohash)
- [toJSON](MasterKey.md#tojson)
- [fromJSON](MasterKey.md#fromjson)
- [fromSecret](MasterKey.md#fromsecret)

## Constructors

### constructor

• **new MasterKey**(`port`, `from`, `to`, `na`, `nb`, `secret`, `encryptKey`, `decryptKey`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `port` | `number` |
| `from` | [`Identity`](../interfaces/Identity.md) |
| `to` | [`Identity`](../interfaces/Identity.md) |
| `na` | `Uint8Array` |
| `nb` | `Uint8Array` |
| `secret` | `Uint8Array` |
| `encryptKey` | `Uint8Array` |
| `decryptKey` | `Uint8Array` |

#### Defined in

[src/ts/protocol/master-key.ts:28](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L28)

## Properties

### cipher

• `Protected` **cipher**: `BaseCipher`

#### Defined in

[src/ts/protocol/master-key.ts:25](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L25)

___

### decipher

• `Protected` **decipher**: `BaseCipher`

#### Defined in

[src/ts/protocol/master-key.ts:26](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L26)

___

### from

• `Readonly` **from**: [`Identity`](../interfaces/Identity.md)

#### Defined in

[src/ts/protocol/master-key.ts:30](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L30)

___

### na

• `Readonly` **na**: `Uint8Array`

#### Defined in

[src/ts/protocol/master-key.ts:32](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L32)

___

### nb

• `Readonly` **nb**: `Uint8Array`

#### Defined in

[src/ts/protocol/master-key.ts:33](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L33)

___

### port

• `Readonly` **port**: `number`

#### Defined in

[src/ts/protocol/master-key.ts:29](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L29)

___

### secret

• `Protected` **secret**: `Uint8Array`

#### Defined in

[src/ts/protocol/master-key.ts:34](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L34)

___

### to

• `Readonly` **to**: [`Identity`](../interfaces/Identity.md)

#### Defined in

[src/ts/protocol/master-key.ts:31](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L31)

## Methods

### decrypt

▸ **decrypt**(`ciphertext`): `Promise`<`Uint8Array`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `ciphertext` | `Uint8Array` |

#### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[src/ts/protocol/master-key.ts:46](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L46)

___

### encrypt

▸ **encrypt**(`message`): `Promise`<`Uint8Array`\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `message` | `Uint8Array` |

#### Returns

`Promise`<`Uint8Array`\>

#### Defined in

[src/ts/protocol/master-key.ts:42](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L42)

___

### fromHash

▸ **fromHash**(): `Promise`<`string`\>

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/protocol/master-key.ts:61](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L61)

___

### toHash

▸ **toHash**(): `Promise`<`string`\>

#### Returns

`Promise`<`string`\>

#### Defined in

[src/ts/protocol/master-key.ts:65](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L65)

___

### toJSON

▸ **toJSON**(): `any`

#### Returns

`any`

#### Defined in

[src/ts/protocol/master-key.ts:50](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L50)

___

### fromJSON

▸ `Static` **fromJSON**(`data`): `Promise`<[`MasterKey`](MasterKey.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `any` |

#### Returns

`Promise`<[`MasterKey`](MasterKey.md)\>

#### Defined in

[src/ts/protocol/master-key.ts:79](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L79)

___

### fromSecret

▸ `Static` **fromSecret**(`port`, `from`, `to`, `na`, `nb`, `secret`): `Promise`<[`MasterKey`](MasterKey.md)\>

#### Parameters

| Name | Type |
| :------ | :------ |
| `port` | `number` |
| `from` | [`Identity`](../interfaces/Identity.md) |
| `to` | [`Identity`](../interfaces/Identity.md) |
| `na` | `Uint8Array` |
| `nb` | `Uint8Array` |
| `secret` | `Uint8Array` |

#### Returns

`Promise`<[`MasterKey`](MasterKey.md)\>

#### Defined in

[src/ts/protocol/master-key.ts:69](https://gitlab.com/i3-market/code/wp3/t3.2/i3m-wallet-monorepo/-/blob/645d0838/packages/wallet-protocol/src/ts/protocol/master-key.ts#L69)
