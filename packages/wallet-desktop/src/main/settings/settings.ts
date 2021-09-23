import ElectronStore, { Options as ElectronStoreOptions } from 'electron-store'
import _ from 'lodash'

import { Settings as SettingsModel, createDefaultSettings } from '@wallet/lib'
import { logger } from '@wallet/main/internal'

export type Settings = ElectronStore<SettingsModel>
export type SettingsOptions = ElectronStoreOptions<SettingsModel>

export const initSettings = (options: SettingsOptions): Settings => {
  const fixedOptions = _.merge<SettingsOptions, SettingsOptions>({
    defaults: createDefaultSettings()
  }, options)

  // TODO: Check if the settings format is corret. If not fix corrupted data
  const settings = new ElectronStore<SettingsModel>(fixedOptions)
  logger.debug(`Load settings from '${settings.path}'`)

  return settings
}
