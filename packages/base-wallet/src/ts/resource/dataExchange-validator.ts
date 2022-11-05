import { DataExchangeResource } from '../app'
import { Validator } from './resource-validator'
export const dataExchangeValidator: Validator<DataExchangeResource> = async (resource, veramo) => {
  const errors: Error[] = []

  errors.push(new Error('NOT IMPLEMENTED. The data exchange will be automatically added when adding a valid nr proof'))

  return errors
}
