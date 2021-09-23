
import { BrowserWindow, BrowserWindowConstructorOptions } from 'electron'
import { Observable, Subject } from 'rxjs'
import { catchError, first, pluck, switchMap } from 'rxjs/operators'

import { ActionRequest, SharedMemorySync, TypedObject, WindowInput, WindowOutput, withType } from '@wallet/lib'
import { Locals, logger } from '@wallet/main/internal'

export type Mapper<T> = (...args: any[]) => T

export class CustomWindow<
  I extends WindowInput | TypedObject<string> = WindowInput,
  O extends WindowOutput | TypedObject<string> = WindowOutput
> extends BrowserWindow {
  input$: Subject<I>
  output$: Observable<O>

  constructor (protected locals: Locals, options?: BrowserWindowConstructorOptions) {
    super(options)
    const { sharedMemoryManager } = this.locals
    const _response$ = new Subject<O>()
    this.input$ = new Subject<I>()

    this.on('focus', () => {
      this.flashFrame(false)
    })

    this.webContents.on('ipc-message', (ev, channel, value: O) => {
      if (channel === 'output') {
        _response$.next(value)
      }
    })

    this.input$.subscribe(msg => {
      this.webContents.send('input', msg)
    })

    this.on('close', () => {
      _response$.complete()
      this.destroy()
    })

    this.output$ = _response$

    this.output$
      .pipe(withType('memory-sync'))
      .subscribe((memorySync) => {
        sharedMemoryManager.update((memorySync as any as SharedMemorySync).memory, this)
      })

    this.output$
      .pipe(
        withType('action'),
        switchMap(async (actionRequest) => {
          await this.locals.actionReducer.reduce((actionRequest as any as ActionRequest).action)
        }),
        catchError((err, caught) => {
          logger.error(err)
          return caught
        })
      )
      .subscribe()

    this.output$
      .pipe(
        withType('memory-request'),
        pluck('memory')
      )
      .subscribe(() => this.updateSharedMemory())
  }

  updateSharedMemory (emitter?: BrowserWindow): void {
    if (emitter === this) {
      return
    }
    const memSync: SharedMemorySync = {
      type: 'memory-sync',
      memory: this.locals.sharedMemoryManager.memory
    }
    // TODO: Fix this ignore?
    // @ts-expect-error
    this.input$.next(memSync)
  }

  // eslint-disable-next-line @typescript-eslint/promise-function-async
  getInput (): Promise<O> {
    return this.output$.pipe(first()).toPromise()
  }
}
