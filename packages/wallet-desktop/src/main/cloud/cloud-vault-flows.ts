import { Identity, VerifiableCredentialResource } from '@i3m/base-wallet'
import { passwordCheck } from '@i3m/cloud-vault-client'
import { Credentials, DEFAULT_CLOUD_URL, DEFAULT_VAULT_PROVIDERS, filled } from '@wallet/lib'

import { getVersionDate, handleError, LabeledTaskHandler, Locals, WalletDesktopError } from '@wallet/main/internal'
import { SyncDirection } from './sync-manager'

interface RegistrationIdentity {
  identity: Identity
  provider?: boolean
  consumer?: boolean
}

export class CloudVaultFlows {
  constructor (protected locals: Locals) {}

  async firstTimeSync (task: LabeledTaskHandler): Promise<void> {
    const { dialog, cloudVaultManager } = this.locals
    const initialTaskDetails = task.task.description.details ?? ''
    task.setDetails('Setting up your cloud vault').update()

    const loginBuilder = dialog.useOptionsBuilder()
    loginBuilder.add('No', 'danger')
    const login = loginBuilder.add('Yes')

    let sync = false
    while (!sync) {
      const option = await dialog.select({
        title: 'Secure Cloud Vault',
        message: 'If you already have a backup in a cloud vault server, do you want to load it?',
        showInput: false,
        ...loginBuilder
      })

      if (loginBuilder.compare(option, login)) {
        try {
          await cloudVaultManager.loginTask(task, { freezing: true })
          sync = true
          continue
        } catch (err: unknown) {
          await handleError(this.locals, err)
        }
      } else {
        break
      }
    }

    if (sync) {
      task.setDetails('Restoring your cloud vault data').update()
      await this.locals.syncManager.sync({ direction: 'pull', force: true })
    }

    task.setDetails(initialTaskDetails).update()
  }

  async askConflictResolution (localTimestamp?: number, remoteTimestamp?: number): Promise<SyncDirection> {
    const { dialog } = this.locals

    const optionBuilder = dialog.useOptionsBuilder()
    const remote = optionBuilder.add('Remote version')
    const local = optionBuilder.add('Local version')
    optionBuilder.add('Cancel', 'danger')

    const localVersion = getVersionDate(localTimestamp)
    const remoteVersion = getVersionDate(remoteTimestamp)

    const response = await dialog.select({
      title: 'Cloud Vault',
      message: `There has been a conflict between the local version (${localVersion}) and the remote version ('${remoteVersion}).\n\n Which version would you want to use?`,
      allowCancel: true,
      showInput: false,
      ...optionBuilder
    })

    if (optionBuilder.compare(remote, response)) {
      return 'pull'
    } else if (optionBuilder.compare(local, response)) {
      return 'push'
    }

    return 'none'
  }

  async askCloudVaultUrl (): Promise<string> {
    const { storeManager, sharedMemoryManager: shm, dialog } = this.locals
    const cloud = shm.memory.settings.public.cloud
    let url = cloud?.url

    if (!filled(url)) {
      const vaultUrl = await dialog.select({
        title: 'Cloud Vault',
        message: `You must provide the URL of your Cloud Vault server (i.e. ${DEFAULT_CLOUD_URL})`,
        allowCancel: true,
        freeAnswer: true,
        values: DEFAULT_VAULT_PROVIDERS
      })

      if (vaultUrl !== undefined) {
        url = vaultUrl
        await storeManager.silentStoreVaultUrl(vaultUrl)
      }
    }

    if (url === undefined) {
      throw new WalletDesktopError('Invalid URL for the Cloud Vault server', {
        message: 'Cloud Vault',
        details: 'Invalid URL for the Cloud Vault server'
      })
    }

    return url
  }

  async askCredentials (errorMessage: string, opts?: { credentials?: Credentials, store?: boolean}): Promise<Credentials> {
    const { dialog, sharedMemoryManager: shm, storeManager } = this.locals
    let credentials = opts?.credentials
    const storeCredentials = opts?.store ?? false

    if (credentials !== undefined) {
      return credentials
    }

    const cloud = shm.memory.settings.private.cloud
    if (cloud?.credentials !== undefined) {
      return cloud.credentials
    }

    credentials = await dialog.form<Credentials>({
      title: 'Cloud Vault',
      descriptors: {
        username: { type: 'text', message: 'Introduce your username' },
        password: { type: 'text', message: 'Introduce your password', hiddenText: true }
      },
      order: ['username', 'password']
    })
    if (credentials === undefined) {
      throw new WalletDesktopError('You need to provide a valid username and password.', {
        severity: 'error',
        message: errorMessage,
        details: 'You need to provide a valid username and password.'
      })
    }

    passwordCheck(credentials.password)
    if (storeCredentials) {
      await storeManager.silentStoreCredentials(credentials)
    }

    return credentials
  }

  async askPasswordConfirmation (credential: Credentials): Promise<void> {
    const { dialog } = this.locals
    const totalTries = 3
    let triesLeft = totalTries
    while (triesLeft > 0) {
      const password = await dialog.text({
        message: `Confirm the password (${triesLeft}/${totalTries} tries left).`,
        hiddenText: true
      })

      if (password === credential.password) {
        return
      }
      triesLeft--
    }

    throw new WalletDesktopError('Confirmation password does not match', {
      severity: 'warning',
      message: 'Cloud Vault Registration',
      details: 'Confirmation password does not match'
    })
  }

  async askRegistrationCredential (errorMessage: string): Promise<RegistrationIdentity> {
    const { dialog, sharedMemoryManager: shm } = this.locals

    const resources = Object.values(this.locals.sharedMemoryManager.memory.resources)
    const vcs = resources.filter((resource) => {
      if (resource?.type !== 'VerifiableCredential') return false

      const subject = resource.resource.credentialSubject
      if (subject.consumer === true || subject.provider === true) {
        return true
      }
      return false
    }) as VerifiableCredentialResource[]

    const { identities } = shm.memory
    const possibleIdentities: Record<string /* DID */, RegistrationIdentity> = {}
    for (const vc of vcs) {
      if (vc.identity !== undefined) {
        const identity = identities[vc.identity]
        if (identity === undefined) {
          continue
        }

        const subject = vc.resource.credentialSubject
        let regIdentity: RegistrationIdentity
        if (possibleIdentities[vc.identity] !== undefined) {
          regIdentity = possibleIdentities[vc.identity]
        } else {
          regIdentity = { identity }
          possibleIdentities[vc.identity] = regIdentity
        }

        if (subject.consumer === true) {
          regIdentity.consumer = true
        }

        if (subject.provider === true) {
          regIdentity.provider = true
        }
      }
    }

    const possibleIdentitiesList = Object.values(possibleIdentities)
    let reg: RegistrationIdentity | undefined
    if (possibleIdentitiesList.length > 1) {
      const response = await dialog.select({
        title: 'Cloud Vault',
        message: 'Select a valid i3-market identity to register it into the vault server.',
        values: possibleIdentitiesList,
        getText (reg) {
          const alias = reg.identity.alias
          const name = alias !== undefined ? alias : (reg.identity.did.substring(0, 23) + '...')
          const types: string[] = []
          if (reg.consumer === true) {
            types.push('Consumer')
          }

          if (reg.provider === true) {
            types.push('Provider')
          }

          return `${name} (as ${types.join('/')})`
        }
      })

      reg = response
    } else {
      reg = possibleIdentitiesList[0]
    }

    if (reg === undefined) {
      throw new WalletDesktopError('You need a valid provider/consumer i3-market credential to register a user', {
        severity: 'error',
        message: errorMessage,
        details: 'You need a valid provider/consumer i3-market credential to register a user'
      })
    }

    return reg
  }
}
