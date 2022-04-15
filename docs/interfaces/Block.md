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

[src/ts/types.ts:44](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/types.ts#L44)

___

### poo

• `Optional` **poo**: [`StoredProof`](StoredProof.md)<[`PoOPayload`](PoOPayload.md)\>

#### Defined in

[src/ts/types.ts:49](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/types.ts#L49)

___

### pop

• `Optional` **pop**: [`StoredProof`](StoredProof.md)<[`PoPPayload`](PoPPayload.md)\>

#### Defined in

[src/ts/types.ts:51](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/types.ts#L51)

___

### por

• `Optional` **por**: [`StoredProof`](StoredProof.md)<[`PoRPayload`](PoRPayload.md)\>

#### Defined in

[src/ts/types.ts:50](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/types.ts#L50)

___

### raw

• `Optional` **raw**: `Uint8Array`

#### Defined in

[src/ts/types.ts:43](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/types.ts#L43)

___

### secret

• `Optional` **secret**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `hex` | `string` |
| `jwk` | [`JWK`](JWK.md) |

#### Defined in

[src/ts/types.ts:45](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/00bfe7f/src/ts/types.ts#L45)
