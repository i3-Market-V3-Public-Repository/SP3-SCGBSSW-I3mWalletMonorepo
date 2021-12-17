# Interface: OrigBlock

## Hierarchy

- [`Block`](Block.md)

  ↳ **`OrigBlock`**

## Table of contents

### Properties

- [jwe](OrigBlock.md#jwe)
- [poo](OrigBlock.md#poo)
- [pop](OrigBlock.md#pop)
- [por](OrigBlock.md#por)
- [raw](OrigBlock.md#raw)
- [secret](OrigBlock.md#secret)

## Properties

### jwe

• **jwe**: `string`

#### Overrides

[Block](Block.md).[jwe](Block.md#jwe)

#### Defined in

[src/ts/types.ts:59](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c516486/src/ts/types.ts#L59)

___

### poo

• `Optional` **poo**: [`StoredProof`](StoredProof.md)<[`PoOPayload`](PoOPayload.md)\>

#### Inherited from

[Block](Block.md).[poo](Block.md#poo)

#### Defined in

[src/ts/types.ts:52](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c516486/src/ts/types.ts#L52)

___

### pop

• `Optional` **pop**: [`StoredProof`](StoredProof.md)<[`PoPPayload`](PoPPayload.md)\>

#### Inherited from

[Block](Block.md).[pop](Block.md#pop)

#### Defined in

[src/ts/types.ts:54](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c516486/src/ts/types.ts#L54)

___

### por

• `Optional` **por**: [`StoredProof`](StoredProof.md)<[`PoRPayload`](PoRPayload.md)\>

#### Inherited from

[Block](Block.md).[por](Block.md#por)

#### Defined in

[src/ts/types.ts:53](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c516486/src/ts/types.ts#L53)

___

### raw

• **raw**: `Uint8Array`

#### Overrides

[Block](Block.md).[raw](Block.md#raw)

#### Defined in

[src/ts/types.ts:58](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c516486/src/ts/types.ts#L58)

___

### secret

• **secret**: `Object`

#### Type declaration

| Name | Type |
| :------ | :------ |
| `hex` | `string` |
| `jwk` | [`JWK`](JWK.md) |

#### Overrides

[Block](Block.md).[secret](Block.md#secret)

#### Defined in

[src/ts/types.ts:60](https://gitlab.com/i3-market/code/wp3/t3.2/conflict-resolution/non-repudiation-library/-/blob/c516486/src/ts/types.ts#L60)
