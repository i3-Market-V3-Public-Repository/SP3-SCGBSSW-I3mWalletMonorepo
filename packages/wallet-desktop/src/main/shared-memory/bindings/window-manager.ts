import { Locals } from '@wallet/main/internal'

export const bindWindowManager = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager, windowManager } = locals

  // Update the shared memory on the views
  sharedMemoryManager.on('change', ({ ctx }) => {
    for (const [, window] of windowManager.windows) {
      window.updateSharedMemory(ctx?.emitter)
    }
  })
}
