import { KeyObject } from 'crypto'

export function isKeyObject (key: unknown): key is KeyObject {
  if (key instanceof KeyObject) {
    return true
  }
  return false
}
