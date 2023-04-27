import { checkErrorType, VaultError } from '@i3m/cloud-vault-client'
import { AsyncEventHandler, Locals, MainContext, WalletDesktopError } from '@wallet/main/internal'

export type SyncDirection = 'pull' | 'push' | 'none'
export type ResolveFunction = (direction: SyncDirection, force?: boolean) => Promise<void>


interface UpdateSyncEvent {
  force?: boolean
  direction: SyncDirection
}

interface ConflictSyncEvent {
  resolve: ResolveFunction
}

interface SyncTimestamps {
  local?: number
  remote?: number
}

interface SynchronizeContext {
  timestamps: SyncTimestamps

  direction?: SyncDirection
  force?: boolean
}

export type SyncEvent = UpdateSyncEvent | ConflictSyncEvent

interface SyncEvents {
  'conflict': [ConflictSyncEvent]
  'update': [UpdateSyncEvent]
}


export class SynchronizationManager extends AsyncEventHandler<SyncEvents> {

  static async initialize (ctx: MainContext, locals: Locals): Promise<SynchronizationManager> {
    return new SynchronizationManager(locals)
  }

  constructor (protected locals: Locals) {
    super()

    this.resolve.bind(this)
  }

  protected resolve: ResolveFunction = async (direction, force) => {
    try {
      await this.emit('update', { direction, force })
    } catch (err) {
      if (err instanceof VaultError) {
        console.trace(err)
        if (checkErrorType(err, 'conflict')) {
          return await this.emit('conflict', { resolve: this.resolve})
        }
      }
      throw err
    }
  }

  async sync (opts: SynchronizeContext): Promise<void> {
    const { sharedMemoryManager } = this.locals
    const cloud = sharedMemoryManager.memory.settings.public.cloud

    let conflict = false
    let direction: SyncDirection | undefined = opts.direction
    if (direction === undefined) {
      const fixedRemoteTimestamp = opts.timestamps.remote ?? 0
      const fixedLocalTimestamp = opts.timestamps.local ?? 0
      const unsyncedChanges = cloud?.unsyncedChanges ?? false
  
      if (fixedRemoteTimestamp > fixedLocalTimestamp) {
        if (unsyncedChanges && opts.force !== true) {
          conflict = true
        } else {
          direction = 'pull'
        }
      } else if (unsyncedChanges) {
        direction = 'push'
      } else {
        direction = 'none'
      }
    }

    if (conflict) {
      await this.conflict()
    } else {
      if (direction !== undefined) {
        await this.resolve(direction, opts.force)
      } else {
        throw new WalletDesktopError('Invalid cloud vault synchronization', {
          message: 'Cloud vault synchronization',
          severity: 'error'
        })
      }
    }
  }

  async conflict (): Promise<void> {
    await this.emit('conflict', { resolve: this.resolve })
  }

}
