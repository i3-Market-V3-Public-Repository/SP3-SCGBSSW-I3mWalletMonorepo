import { OpenApiValidatorOpts } from 'express-openapi-validator/dist/openapi.validator'
import path from 'path/posix'
import { general } from './general'

export const apiVersion = `v${general.version.split('.')[0]}`
const regexIgnorePaths = `/api/${apiVersion}/vault/notifications$`
export const openApi: Omit<OpenApiValidatorOpts, 'apiSpec'> & { apiSpec: string } = {
  apiSpec: path.join(__dirname, '..', 'spec', 'openapi.yaml'),
  validateResponses: general.nodeEnv === 'development', // <-- validate responses in development mode
  // validateResponses: false,
  validateRequests: true,
  validateApiSpec: true,
  ignorePaths: new RegExp(regexIgnorePaths)
}
