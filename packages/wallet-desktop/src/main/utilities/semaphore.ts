
import { v4 as uuid } from 'uuid'

type RunMethod = () => Promise<void>

export class Semaphore {
  runningRecord: Record<string, Promise<void>>
  constructor () {
    this.runningRecord = {}
  }

  get running (): Array<Promise<void>> {
    return Object.values(this.runningRecord)
  }

  async wait (runner: RunMethod): Promise<void> {
    const id = uuid()
    const run = new Promise<void>((resolve, reject) => {
      Promise.all(this.running).catch(() => {}).finally(() => {
        this.runningRecord[id] = run
        runner().then(() => {
          resolve()
        }).catch(err => {
          reject(err)
        }).finally(() => {
          delete this.runningRecord[id] // eslint-disable-line @typescript-eslint/no-dynamic-delete
        })
      })
    })

    await run
  }
}
