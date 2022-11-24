import { SharedMemory } from '@wallet/lib'
import { ActionDispatcher } from '@wallet/renderer/communication'

interface BaseSettingsMetadata<T = any> {
  label: string
  key: string
  canUpdate?: (key: string, value: any, metadata: SettingsMetadata, sharedMemory: SharedMemory, dispatch: ActionDispatcher) => boolean
  description?: {
    message: ((item: SettingsMetadata, value: T) => JSX.Element) | JSX.Element
    visible?: ((item: SettingsMetadata, value: T) => boolean) | boolean
  }
}

export interface CheckboxSettingsMetadata extends BaseSettingsMetadata<boolean> {
  type: 'checkbox'
}

export interface InputSettingsMetadata extends BaseSettingsMetadata<string> {
  type: 'input'
}

export interface NumberSettingsMetadata extends BaseSettingsMetadata<number> {
  type: 'number'
}

export interface ArraySettingsMetadata<T = any, S extends BaseSettingsMetadata = SettingsMetadata> extends BaseSettingsMetadata<T[]> {
  type: 'array'
  canDelete?: (i: number, item: T, sharedMemory: SharedMemory, dispatch: ActionDispatcher) => boolean
  defaults: (parent: SettingsMetadata, value: T[]) => T
  innerType: (i: number, parent: SettingsMetadata) => S
}

export interface ObjectSettingsMetadata<T extends Record<string, any> = any> extends BaseSettingsMetadata<T> {
  type: 'object'
  innerType: {
    [P in keyof T]?: SettingsMetadata
  }
}

export type SettingsMetadata =
  CheckboxSettingsMetadata |
  InputSettingsMetadata |
  NumberSettingsMetadata |
  ArraySettingsMetadata |
  ObjectSettingsMetadata

export type SettingsMetadataRecord = Record<string, SettingsMetadata[]>
