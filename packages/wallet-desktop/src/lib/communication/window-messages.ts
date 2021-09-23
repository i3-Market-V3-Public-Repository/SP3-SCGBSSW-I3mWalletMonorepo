import { Action } from '../internal'
import { SharedMemory } from './shared-memory'

export interface SharedMemorySync {
  type: 'memory-sync'
  memory: SharedMemory
}

export interface SharedMemoryRequest {
  type: 'memory-request'
}

export interface ActionRequest {
  type: 'action'
  action: Action
}

export type WindowOutput = SharedMemorySync | SharedMemoryRequest | ActionRequest

export type WindowInput = SharedMemorySync
