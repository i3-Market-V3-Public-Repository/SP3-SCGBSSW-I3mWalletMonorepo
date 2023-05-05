
import { v4 as uuid } from 'uuid'

type RunMethod = () => Promise<void>

export class Semaphore {
  runningRecord: Record<string, Promise<void>>
  constructor () {
    this.runningRecord = {}
  }

  get running(): Array<Promise<void>> {
    return Object.values(this.runningRecord)
  }

  async wait (runner: RunMethod): Promise<void> {
    const id = uuid()
    const run = new Promise<void>(async (resolve, reject) => {
      await Promise.all(this.running).catch(() => {})

      try {
        this.runningRecord[id] = run
        await runner()
        resolve()
      } catch (err) {
        reject(err)
      } finally {
        delete this.runningRecord[id]
      }
    })

    await run
  }
}
