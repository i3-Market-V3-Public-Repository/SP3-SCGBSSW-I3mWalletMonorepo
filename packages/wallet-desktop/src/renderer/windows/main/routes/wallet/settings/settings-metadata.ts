import { SharedMemory } from '@wallet/lib'
import { ActionDispatcher } from '@wallet/renderer/communication'

export interface BaseMetadata<T = any> {
  description?: {
    title?: string
    message: ((item: ItemMetadata, value: T) => JSX.Element) | JSX.Element
    visible?: ((item: ItemMetadata, value: T) => boolean) | boolean
  }
}

export interface InfoMetadata extends BaseMetadata<never> {
  type: 'info'
}

export type SettingsValueOrFunction<V, T> = V | ((key: string, value: T, metadata: SettingsMetadata, sharedMemory: SharedMemory) => V)

interface BaseSettingsMetadata<T = any> extends BaseMetadata<T> {
  label: SettingsValueOrFunction<string, T>
  key: string
  default?: T
  canUpdate?: (key: string, value: any, metadata: SettingsMetadata, sharedMemory: SharedMemory, dispatch: ActionDispatcher) => boolean
}

export interface CheckboxSettingsMetadata extends BaseSettingsMetadata<boolean> {
  type: 'checkbox'
}

export interface AutocompleteSettingsMetadata extends BaseSettingsMetadata<string> {
  type: 'autocomplete'
  placeholder?: string
  options: string[]
}

export interface InputSettingsMetadata extends BaseSettingsMetadata<string> {
  type: 'input'
  placeholder?: string
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
  AutocompleteSettingsMetadata |
  NumberSettingsMetadata |
  ArraySettingsMetadata |
  ObjectSettingsMetadata

export type ItemMetadata = SettingsMetadata | InfoMetadata

export type MetadataRecord = Record<string, ItemMetadata[]>
