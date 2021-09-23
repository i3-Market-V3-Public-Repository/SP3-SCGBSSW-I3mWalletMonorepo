import path from 'path'
import { getContext } from '@wallet/lib'

export const getResourcePath = (resPath: string): string => {
  const ctx = getContext()
  return path.resolve(ctx.appPath, 'res', resPath)
}
