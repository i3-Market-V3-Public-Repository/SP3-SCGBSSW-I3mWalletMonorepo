import type { OpenApiValidatorOpts } from 'express-openapi-validator/dist/openapi.validator'
import { join } from 'node:path'
import { general } from './general'

export const apiVersion = `v${general.version.split('.')[0]}`
export const openApi: Omit<OpenApiValidatorOpts, 'apiSpec'> & { apiSpec: string } = {
  apiSpec: join(__dirname, '..', 'spec', 'openapi.yaml'),
  validateResponses: true,
  validateRequests: true,
  validateApiSpec: true
}
