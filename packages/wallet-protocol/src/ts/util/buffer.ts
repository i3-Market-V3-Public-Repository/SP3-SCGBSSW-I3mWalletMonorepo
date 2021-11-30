export const bufferUtils = {
  join: (...list: Uint8Array[]): Uint8Array => {
    const size = list.reduce((a, b) => a + b.length, 0)
    const buffer = new Uint8Array(size)
    let accLen = 0
    for (const el of list) {
      buffer.set(el, accLen)
      accLen += el.length
    }

    return buffer
  },

  split: (buffer: Uint8Array, ...sizes: number[]): Uint8Array[] => {
    const list: Uint8Array[] = []
    let start = 0
    for (const size of sizes) {
      list.push(buffer.slice(start, start + size))
      start += size
    }

    return list
  },

  insertBytes: (src: Uint8Array, dst: Uint8Array, fromStart: number, toStart: number, size: number) => {
    for (let i = 0; i < size; i++) {
      dst[i + toStart] = src[i + fromStart]
    }
  },

  insertBits: (src: Uint8Array, dst: Uint8Array, fromStart: number, toStart: number, size: number) => {
    let fromByteIndex = Math.floor(fromStart / 8)
    let fromBitIndex = fromStart % 8
    let toByteIndex = Math.floor(toStart / 8)
    let toBitIndex = toStart % 8
    let currFromByte = src[fromByteIndex] ?? 0
    const deltaOffset = toBitIndex - fromBitIndex

    for (let i = 0; i < size; i++) {
      let currBit: number
      if (deltaOffset >= 0) {
        currBit = ((currFromByte & (128 >> fromBitIndex)) << deltaOffset)
      } else {
        currBit = ((currFromByte & (128 >> fromBitIndex)))
      }

      const bitSet = ((dst[toByteIndex] & ~(128 >> toBitIndex)) | currBit)
      dst[toByteIndex] = bitSet

      // Move pointers
      fromBitIndex++
      toBitIndex++
      if (fromBitIndex >= 8) {
        fromByteIndex++
        fromBitIndex = 0
        currFromByte = src[fromByteIndex] ?? 0
      }
      if (toBitIndex >= 8) {
        toByteIndex++
        toBitIndex = 0
      }
    }
  },

  extractBits: (buf: Uint8Array, start: number, size: number): Uint8Array => {
    const byteSize = Math.ceil(size / 8)
    const dst = new Uint8Array(byteSize)
    bufferUtils.insertBits(buf, dst, start, 0, size)

    return dst
  }
}
