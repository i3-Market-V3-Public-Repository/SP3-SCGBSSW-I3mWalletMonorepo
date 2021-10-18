
interface BaseSettingsMetadata {
  label: string
  key: string
}

export interface CheckboxSettingsMetadata extends BaseSettingsMetadata {
  type: 'checkbox'
}

export interface InputSettingsMetadata extends BaseSettingsMetadata {
  type: 'input'
}

export type SettingsMetadata = CheckboxSettingsMetadata | InputSettingsMetadata
