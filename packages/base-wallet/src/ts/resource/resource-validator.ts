import { WalletComponents } from '@i3m/wallet-desktop-openapi/types'
import Veramo from '../veramo'
import { contractValidator } from './contract-validator'
import { dataExchangeValidator } from './dataExchange-validator'
import { nrpValidator } from './nrp-validator'
import { objectValidator } from './object-validator'
import { verifiableClaimValidator } from './vc-validator'

interface Validation {
  validated: boolean
  errors: Error[]
}

export type ResourceType = WalletComponents.Schemas.ResourceType
export type Resource = WalletComponents.Schemas.Resource
export type Validator<T extends Resource> = (resource: T, veramo: Veramo) => Promise<Error[]>

export class ResourceValidator {
  protected validators: { [key: string]: Validator<any> | undefined }

  constructor () {
    this.validators = {}
    this.initValidators()
  }

  private initValidators (): void {
    this.setValidator('VerifiableCredential', verifiableClaimValidator)
    this.setValidator('Object', objectValidator)
    this.setValidator('Contract', contractValidator)
    this.setValidator('DataExchange', dataExchangeValidator)
    this.setValidator('NonRepudiationProof', nrpValidator)
  }

  private setValidator (name: ResourceType, validator: Validator<any>): void {
    this.validators[name] = validator
  }

  async validate (resource: Resource, veramo: Veramo): Promise<Validation> {
    const validation: Validation = {
      validated: false,
      errors: []
    }

    const validator = this.validators[resource.type]
    if (validator !== undefined) {
      validation.errors = await validator(resource, veramo)
      validation.validated = true
    }

    return validation
  }
}
