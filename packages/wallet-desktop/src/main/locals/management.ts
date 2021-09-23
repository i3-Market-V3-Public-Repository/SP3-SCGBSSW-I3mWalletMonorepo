import { Application } from 'express'

import { Locals } from './model'

export const extractLocals = (app: Application): Locals => {
  return app.locals.appLocals as Locals
}

export const setLocals = (app: Application, locals: Locals): void => {
  app.locals = {
    ...app.locals,
    appLocals: locals
  }
}
