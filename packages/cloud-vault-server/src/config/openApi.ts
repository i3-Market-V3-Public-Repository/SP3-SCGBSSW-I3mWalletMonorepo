import type { OpenApiValidatorOpts } from 'express-openapi-validator/dist/openapi.validator.js'
import { join } from 'node:path'
import { general } from './general.js'

export const apiVersion = `v${general.version.split('.')[0]}`
export const openApi: Omit<OpenApiValidatorOpts, 'apiSpec'> & { apiSpec: string } = {
  apiSpec: join(__dirname, '..', 'spec', 'cvs.yaml'),
  validateResponses: true,
  validateRequests: true,
  validateApiSpec: true
}
