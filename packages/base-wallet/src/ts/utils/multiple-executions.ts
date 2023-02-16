import Debug from 'debug'
import { basename } from 'path'
import { bufferCount, Observable, timeout } from 'rxjs'

const debug = Debug('base-wallet' + basename(__filename))

export interface MultipleExecutionsOptions {
  successRate?: number // the required success rate as a float [0, 1]. 0 means that it is enough with one to succeed; .5 means to wait for a half to succeed (and provide the same result). Default is 0
  timeout?: number // maximum elapsed time in milliseconds between values acquired from the executors. Defaults to 10000.
}

export async function multipleExecutions<T extends any> (options: MultipleExecutionsOptions, executors: any[], fnName: string, ...args: any[]): Promise<T[]> {
  if (executors.length < 1 || executors[0][fnName] === undefined) {
    throw new Error('invalid executors')
  }

  /** By default, if n executors, it is enough with 1 to succeed  */
  const successRate = options.successRate ?? 0
  if (successRate < 0 || successRate > 1) {
    throw new Error('invalid successRate. It should be a value between 0 and 1 (both included)')
  }
  const minResults = successRate === 0 ? 1 : Math.ceil(successRate * executors.length)

  const _timeout = options.timeout ?? 10000

  const observable = new Observable<T>((subscriber) => {
    let subscriberSFinished: number = 0
    executors.forEach(executor => {
      if (isAsync(executor[fnName])) {
        executor[fnName](...args).then((result: T) => {
          subscriber.next(result)
        }).catch((err: unknown) => {
          debug(err)
        }).finally(() => {
          subscriberSFinished++
          if (subscriberSFinished === executors.length) {
            subscriber.complete()
          }
        })
      } else {
        try {
          const result: T = executor[fnName](...args)
          subscriber.next(result)
        } catch (err: unknown) {
          debug(err)
        } finally {
          subscriberSFinished++
          if (subscriberSFinished === executors.length) {
            subscriber.complete()
          }
        }
      }
    })
  }).pipe(
    bufferCount(minResults),
    timeout(_timeout)
  )

  const results = await new Promise<T[]>((resolve, reject) => {
    const subscription = observable.subscribe({
      next: v => {
        resolve(v)
      },
      error: (e) => {
        debug(e)
        reject(e)
      }
    })
    setTimeout(() => {
      subscription.unsubscribe()
    }, _timeout)
  })

  if (results.length < minResults) {
    throw new Error(`less successful executions (${results.length}) than min requested (${minResults})`)
  }

  return results
}

function isAsync (fn: any): boolean {
  if (fn.constructor.name === 'AsyncFunction') {
    return true
  } else if (fn.constructor.name === 'Function') {
    return false
  }
  throw new Error('not a function')
}
