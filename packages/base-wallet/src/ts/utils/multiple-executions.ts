import Debug from 'debug'
import { basename } from 'path'
import { bufferCount, Observable, timeout } from 'rxjs'

const debug = Debug('base-wallet' + basename(__filename))

export interface MultipleExecutionsOptions {
  successRate?: number // the required success rate as a float [0, 1]. 0 means that it is enough with one to succeed; .5 means to wait for a half to succeed (and provide the same result). Default is 0
  timeout?: number // maximum elapsed time in milliseconds between values acquired from the executors. Defaults to 10000.
}

type FunctionMap<K extends string> = {
  [P in K]: (...args: any) => any
}

type ValueOrResolvedValue<T> = T extends Promise<infer R> ? R : T
export type MultipleExecutionsReturn<K extends string, T extends FunctionMap<K>> = ValueOrResolvedValue<ReturnType<T[K]>>

export async function multipleExecutions<K extends string, T extends FunctionMap<K>> (options: MultipleExecutionsOptions, executors: T[], fnName: K, ...args: any[]): Promise<Array<MultipleExecutionsReturn<K, T>>> {
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

  const observable = new Observable<ValueOrResolvedValue<ReturnType<T[K]>>>((subscriber) => {
    let subscriberSFinished: number = 0
    executors.forEach(executor => {
      const fn = executor[fnName]
      let returnPromise = false
      try {
        const resultOrPromise = fn.call(executor, ...args)
        if (isPromise<ReturnType<T[K]>>(resultOrPromise)) {
          returnPromise = true
          resultOrPromise.then((result) => {
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
          subscriber.next(resultOrPromise)
        }
      } catch (err: unknown) {
        debug(err)
      } finally {
        if (!returnPromise) {
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

  const results = await new Promise<Array<ValueOrResolvedValue<ReturnType<T[K]>>>>((resolve, reject) => {
    const subscription = observable.subscribe({
      next: v => {
        resolve(v)
      }
    })
    setTimeout(() => {
      subscription.unsubscribe()
      reject(new Error('Timeout waiting for results reached'))
    }, _timeout)
  }).catch()

  if (results.length < minResults) {
    throw new Error(`less successful executions (${results.length}) than min requested (${minResults})`)
  }

  return results
}

function isPromise<T> (promise: any): promise is Promise<T> {
  return promise !== undefined && typeof promise.then === 'function'
}
