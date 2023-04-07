import * as OpenApiValidator from 'express-openapi-validator'
import { openApi } from '../config/index.js'

export const openApiValidatorMiddleware = OpenApiValidator.middleware({
  ...openApi
  // formats: [
  //   {
  //     name: 'compact-jws',
  //     type: 'string',
  //     validate: (input: string): boolean => {
  //       const matched = input.match(/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/)
  //       return matched !== null
  //     }
  //   }
  // ]
})
