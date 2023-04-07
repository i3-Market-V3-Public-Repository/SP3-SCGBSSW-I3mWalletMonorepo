import { NextFunction, Request, Response } from 'express'
import { HttpError } from 'express-openapi-validator/dist/framework/types'
import type { OpenApiComponents } from '../../types/openapi.js'
import { general } from '../config/index.js'

export function errorMiddleware (err: unknown, req: Request, res: Response, next: NextFunction): void {
  if (general.nodeEnv === 'development') {
    console.error(err)
  }
  let error: OpenApiComponents.Schemas.ApiError = {
    name: 'error',
    description: 'something bad happened'
  }
  let status = 500
  if (err instanceof HttpError) {
    status = err.status
    error = {
      name: (err.status === 401) ? 'unauthorized' : err.name,
      description: err.message ?? ''
    }
  }
  res.status(status).json(error)
}
