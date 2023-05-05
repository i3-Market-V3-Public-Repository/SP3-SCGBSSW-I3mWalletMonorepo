import { checkErrorType, VaultError, VaultStorage } from '@i3m/cloud-vault-client'
import { AsyncEventHandler, Locals, MainContext, Semaphore, WalletDesktopError } from '@wallet/main/internal'

export type SyncDirection = 'pull' | 'push' | 'none'
export type ResolveFunction = (direction: SyncDirection, force?: boolean) => Promise<void>

interface UpdateSyncEvent {
  force?: boolean
  vault?: VaultStorage
  direction: SyncDirection
}

interface ConflictSyncEvent {
  resolve: ResolveFunction
}

export interface SyncTimestamps {
  local?: number
  remote?: number
}

interface BaseSyncOpts {
  vault?: VaultStorage
  force?: boolean
}

interface AutoSyncOpts extends BaseSyncOpts {
  timestamps: SyncTimestamps
}

interface ForceSyncOpts extends BaseSyncOpts {
  direction: SyncDirection
}

type SyncOpts = AutoSyncOpts | ForceSyncOpts

export type SyncEvent = UpdateSyncEvent | ConflictSyncEvent

interface SyncEvents {
  'conflict': [ConflictSyncEvent]
  'update': [UpdateSyncEvent]
}

function isForceSync (opts: SyncOpts): opts is ForceSyncOpts {
  return Object.hasOwn(opts, 'direction')
}

function isAutoSync (opts: SyncOpts): opts is AutoSyncOpts {
  return Object.hasOwn(opts, 'timestamps')
}

export class SynchronizationManager extends AsyncEventHandler<SyncEvents> {
  static async initialize (ctx: MainContext, locals: Locals): Promise<SynchronizationManager> {
    return new SynchronizationManager(locals)
  }

  semaphore: Semaphore
  constructor (protected locals: Locals) {
    super()

    this.semaphore = new Semaphore()
    this.resolve.bind(this)
  }

  protected resolve: ResolveFunction = async (direction, force) => {
    try {
      await this.emit('update', { direction, force })
    } catch (err) {
      if (err instanceof VaultError) {
        console.trace(err)
        if (checkErrorType(err, 'conflict')) {
          return await this.emit('conflict', { resolve: this.resolve })
        }
      }
      throw err
    }
  }

  async sync (opts: SyncOpts): Promise<void> {
    const { sharedMemoryManager } = this.locals
    const cloud = sharedMemoryManager.memory.settings.public.cloud

    this.semaphore.wait(async () => {
      let conflict = false
      let direction: SyncDirection | undefined
      if (isAutoSync(opts)) {
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
      } else if (isForceSync(opts)) {
        direction = opts.direction
      } else {
        throw new WalletDesktopError('invalid cloud vault sync options', {
          message: 'Cloud Vault Sync',
          severity: 'error',
          details: 'Invalid cloud vault sync options'
        })
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
    })

  }

  async conflict (): Promise<void> {
    await this.emit('conflict', { resolve: this.resolve })
  }
}
