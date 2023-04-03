import { Locals, MainContext } from '@wallet/main/internal'
import { StoreOptions } from './store-builder'

export const getPath = (ctx: MainContext, locals: Locals, options?: Partial<StoreOptions<any>>): string => {
  const fixedOptions = Object.assign({}, {
    cwd: ctx.args.config,
    fileExtension: 'json',
    name: 'config'
  }, options)
  return `${fixedOptions.cwd}/${fixedOptions.name}.${fixedOptions.fileExtension}`
}
