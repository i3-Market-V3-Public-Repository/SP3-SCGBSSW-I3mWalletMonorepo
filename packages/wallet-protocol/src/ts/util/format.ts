import * as base64 from '@juanelas/base64'

export const format = {
  num2U8Arr: (num: number, len?: number): Uint8Array => {
    if (len === undefined) {
      len = 1
      while (2 ** (len * 8) < num) {
        len++
      }
    }
    const arr = new Uint8Array(len)

    let rest = num
    for (let i = len - 1; i >= 0; i--) {
      const nextRest = rest >> 8
      const num = rest - (nextRest << 8)
      arr[i] = num

      rest = nextRest
    }

    return arr
  },

  u8Arr2Num: (buffer: Uint8Array): number => {
    let num = 0
    for (let i = 0; i < buffer.length; i++) {
      num += buffer[i] << ((buffer.length - 1) - i)
    }

    return num
  },

  hex2U8Arr: (hex: string): Uint8Array => {
    const match = hex.match(/.{1,2}/g)
    if (match === null) {
      throw new Error(`not a hex: ${hex}`)
    }

    return new Uint8Array(match.map(byte => parseInt(byte, 16)))
  },

  u8Arr2hex: (arr: Uint8Array): string => {
    return arr.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '')
  },

  u8Arr2Base64: (arr: Uint8Array): string => {
    return base64.encode(arr, true, false)
  },

  base642u8Arr: (b64: string): Uint8Array => {
    return base64.decode(b64, false) as Uint8Array
  }
}
