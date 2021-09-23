export interface BaseContext {
  appPath: string
}

export class UndefinedContext extends Error {
  constructor () {
    super('The context is not initialized yet')
  }
}

export class AlreadyDefinedContext extends Error {
  constructor () {
    super('The context is already initialized')
  }
}

let context: BaseContext | undefined

export const initContext = <T extends BaseContext>(ctx: T): T => {
  if (context !== undefined) {
    throw new AlreadyDefinedContext()
  }

  context = ctx

  return ctx
}

export const getContext = <T extends BaseContext>(): T => {
  if (context === undefined) {
    throw new UndefinedContext()
  }

  return context as T
}
