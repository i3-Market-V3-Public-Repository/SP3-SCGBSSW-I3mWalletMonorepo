import { Subject } from 'rxjs'

import { MainOutput } from '@wallet/lib'

const output$: Subject<MainOutput> = new Subject<MainOutput>()
output$.subscribe((response) => {
  const channel = 'output'
  electron.ipcRenderer.send(channel, response)
})

export function useOutput (): Subject<MainOutput> {
  return output$
}
