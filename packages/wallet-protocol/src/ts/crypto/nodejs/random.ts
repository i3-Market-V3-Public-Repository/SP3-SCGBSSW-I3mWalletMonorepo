import crypto from 'crypto'
import { BaseRandom } from '../types'

class NodeRandom extends BaseRandom {
  async randomFill (buffer: Uint8Array, start: number, size: number): Promise<void> {
    return await new Promise<void>(resolve => {
      crypto.randomFill(buffer, start, size, () => {
        resolve()
      })
    })
  }
}
export const random: BaseRandom = new NodeRandom()
