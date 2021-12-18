# Interface: Block

## Hierarchy

- **`Block`**

  ↳ [`OrigBlock`](OrigBlock.md)

## Table of contents

### Properties

- [jwe](Block.md#jwe)
- [poo](Block.md#poo)
- [pop](Block.md#pop)
- [por](Block.md#por)
- [raw](Block.md#raw)
- [secret](Block.md#secret)

## Properties

### jwe

• `Optional` **jwe**: `string`

#### Defined in

[src/ts/types.ts:47](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/types.ts#L47)

___

### poo

• `Optional` **poo**: [`StoredProof`](StoredProof.md)<[`PoOPayload`](PoOPayload.md)\>

#### Defined in

[src/ts/types.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/types.ts#L52)

___

### pop

• `Optional` **pop**: [`StoredProof`](StoredProof.md)<[`PoPPayload`](PoPPayload.md)\>

#### Defined in

[src/ts/types.ts:54](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/types.ts#L54)

___

### por

• `Optional` **por**: [`StoredProof`](StoredProof.md)<[`PoRPayload`](PoRPayload.md)\>

#### Defined in

[src/ts/types.ts:53](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/types.ts#L53)

___

### raw

• `Optional` **raw**: `Uint8Array`

#### Defined in

[src/ts/types.ts:46](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/types.ts#L46)

___

### secret

• `Optional` **secret**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `hex` | `string` |
| `jwk` | [`JWK`](JWK.md) |

#### Defined in

[src/ts/types.ts:48](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/1e88c9a/src/ts/types.ts#L48)
