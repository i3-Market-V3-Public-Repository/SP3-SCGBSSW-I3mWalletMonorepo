import _ from 'lodash'

import { SharedMemory, createDefaultSharedMemory } from '@wallet/lib'
import { useFilterInput } from './input'
import { useOutput } from './output'

type UpdateSharedMemory = React.Dispatch<Partial<SharedMemory>>

export const SharedMemoryContext = React.createContext<[SharedMemory, UpdateSharedMemory] | null>(null)
SharedMemoryContext.displayName = ' SharedMemoryContext'

export function SharedMemoryProvider (props: React.PropsWithChildren<{}>): JSX.Element {
  const [sharedMemory, _setSharedMemory] = React.useState(createDefaultSharedMemory())
  const output$ = useOutput()
  const useSyncInput = useFilterInput('memory-sync')

  React.useEffect(() => {
    if (SharedMemoryProvider.initialized) {
      return
    }

    output$.next({
      type: 'memory-request'
    })
    SharedMemoryProvider.initialized = true
  }, [])

  useSyncInput((input) => {
    _setSharedMemory(input.memory)
  })

  const setSharedMemory: UpdateSharedMemory = (newSharedMemory) => {
    _setSharedMemory((prevSharedMemory) => {
      const sharedMemory = _.merge({}, prevSharedMemory, newSharedMemory)
      output$.next({
        type: 'memory-sync',
        memory: sharedMemory
      })
      return sharedMemory
    })
  }

  return (
    <SharedMemoryContext.Provider value={[sharedMemory, setSharedMemory]}>
      {props.children}
    </SharedMemoryContext.Provider>
  )
}
SharedMemoryProvider.initialized = false

export function useSharedMemory (): [SharedMemory, UpdateSharedMemory] {
  const ctx = React.useContext(SharedMemoryContext)
  if (ctx === null) {
    throw new Error('Shared memory must be provided using a SharedMemoryProvider component higher in the tree')
  }

  return ctx
}
