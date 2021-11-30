import { BaseRandom } from '../types'

class BrowserRandom extends BaseRandom {
  async randomFill (buffer: Uint8Array, start: number, size: number): Promise<void> {
    const newBuffer = new Uint8Array(size)
    crypto.getRandomValues(newBuffer)
    for (let i = 0; i < size; i++) {
      buffer[start + i] = newBuffer[i]
    }
  }
}
export const random: BaseRandom = new BrowserRandom()
