import { Observable } from 'rxjs'

type IterateFunction<T, R> = (value: T) => Promise<R | undefined>

interface InterateReport<R> {
  completed: boolean
  value?: R
}

// eslint-disable-next-line @typescript-eslint/promise-function-async
export function iterateObservable<T, R> (
  obs$: Observable<T>,
  iter: IterateFunction<T, R>
): Promise<InterateReport<R>> {
  return new Promise<InterateReport<R>>((resolve) => {
    const subscription = obs$.subscribe({
      next (value) {
        iter(value).then(ret => {
          if (ret !== undefined) {
            subscription.unsubscribe()
            resolve({ completed: false, value: ret })
          }
        }).catch(err => {
          throw err
        })
      },
      complete () {
        resolve({ completed: true })
      }
    })
  })
}
