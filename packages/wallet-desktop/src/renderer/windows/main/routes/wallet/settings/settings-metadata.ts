
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

export interface NumberSettingsMetadata extends BaseSettingsMetadata {
  type: 'number'
}

export type SettingsMetadata =
  CheckboxSettingsMetadata |
  InputSettingsMetadata |
  NumberSettingsMetadata
