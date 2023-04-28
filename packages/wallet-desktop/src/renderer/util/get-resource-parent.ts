import { Resource } from '@i3m/base-wallet'
import { SharedMemory } from '@wallet/lib'

interface ParentFilter<T extends Resource> {
  type?: T['type']
}

function checkFilter <T extends Resource>(resource: Resource, filter: ParentFilter<T>): boolean {
  let filterPass = true
  if (filter.type !== undefined) {
    filterPass = filterPass && resource.type === filter.type
  }

  return filterPass
}


export function getResourceParent <T extends Resource>(shm: SharedMemory, resource: Resource, filter: ParentFilter<T>): T  | undefined {
  if (resource.parentResource === undefined) {
    return undefined
  }

  const parent = shm.resources[resource.parentResource]
  if (parent === undefined) {
    return undefined
  }

  if (checkFilter(parent, filter)) {
    return parent as T
  }

  return getResourceParent(shm, parent, filter)
}
