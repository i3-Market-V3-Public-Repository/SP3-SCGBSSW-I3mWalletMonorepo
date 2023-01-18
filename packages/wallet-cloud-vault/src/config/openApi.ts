import { OpenApiValidatorOpts } from 'express-openapi-validator/dist/openapi.validator'
import path from 'path/posix'
import { general } from './general'

export const openApi: Omit<OpenApiValidatorOpts, 'apiSpec'> & { apiSpec: string } = {
  apiSpec: path.join(__dirname, '..', 'spec', 'openapi.yaml'),
  validateResponses: general.nodeEnv === 'development', // <-- validate responses in development mode
  validateRequests: true // always validate requests
}
