import { NextFunction, Request, Response } from 'express'
import { HttpError } from 'express-openapi-validator/dist/framework/types'
import { OpenApiComponents } from '../../types/openapi'
import { general } from '../config'

export function errorMiddleware (err: HttpError, req: Request, res: Response, next: NextFunction): void {
  if (general.nodeEnv === 'development') {
    console.error(err)
  }
  let error: OpenApiComponents.Schemas.ApiError = {
    name: 'error',
    description: 'something bad happened'
  }
  if (req.path !== undefined) {
    if (err.status === undefined) {
      err.status = 500
    } else {
      error = {
        name: err.name,
        description: err.message
      }
    }
  }
  res.status(err.status).json(error)
}
