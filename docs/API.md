my-package-name - v0.9.0

# my-package-name - v0.9.0

My module description. Please update with your module data.

**`remarks`** 
This module runs perfectly in node.js and browsers

## Table of contents

### Functions

- [echo](API.md#echo)
- [sign](API.md#sign)

## Functions

### echo

▸ **echo**(`a`: *string*): *string*

Returns the input string

**`remarks`** An example echo function that runs differently in Node and Browser javascript

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`a` | *string* | the text to echo    |

**Returns:** *string*

a gratifying echo response from either node or browser

Defined in: echo.ts:10

___

### sign

▸ **sign**(`a`: ArrayBufferLike \| *string*): *Promise*<*string*\>

Signs input and returns compact JWS

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`a` | ArrayBufferLike \| *string* | the input to sign    |

**Returns:** *Promise*<*string*\>

a promise that resolves to a compact JWS

Defined in: sign.ts:12
