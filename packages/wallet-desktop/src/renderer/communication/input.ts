import * as React from 'react'

import { MainInput, withType, WithType } from '@wallet/lib'

import { Observable, Subject } from 'rxjs'

type ObservableMap<T, S> = (obs$: Observable<T>) => Observable<S>
type RequestHandler<S> = (v: S) => void
type UseRequestHook<S> = (handler: RequestHandler<S>) => void

const input$: Subject<MainInput> = new Subject<MainInput>()
window.addEventListener('load', () => {
  const channel = 'input'
  const requestListener = (ev: any, msg: MainInput): void => {
    input$.next(msg)
  }

  electron.ipcRenderer.on(channel, requestListener)

  window.addEventListener('unload', () => {
    electron.ipcRenderer.removeListener(channel, requestListener)
    input$.complete()
  })
})

export function useFilterInput (): UseRequestHook<MainInput>
export function useFilterInput<R> (obsMap: ObservableMap<MainInput, R>): UseRequestHook<R>
export function useFilterInput<S extends MainInput['type']> (type: S): UseRequestHook<WithType<MainInput, S>>
export function useFilterInput<S extends MainInput['type'], R extends WithType<MainInput, S>> (input?: ObservableMap<MainInput, R> | S): UseRequestHook<R> {
  return (handler) => {
    React.useEffect(() => {
      let filtered$: Observable<R>
      if (input === undefined) {
        // If obsMap is undefined S = MainRequest but typescript does not
        // solve it automatically... :(

        filtered$ = input$ as any
      } else if (typeof input === 'function') {
        filtered$ = input(input$)
      } else {
        filtered$ = input$.pipe(withType(input)) as any
      }
      const subscription = filtered$.subscribe(handler)

      return () => {
        subscription.unsubscribe()
      }
    }, [])
  }
}
