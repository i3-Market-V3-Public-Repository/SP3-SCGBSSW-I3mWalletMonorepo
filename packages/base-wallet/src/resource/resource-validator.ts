import { WalletComponents } from '@i3-market/wallet-desktop-openapi/types'
import Veramo from '../veramo'
import { verifiableClaimValidator } from './vc-validator'

interface Validation {
  validated: boolean
  errors: Error[]
}

export type ResourceType = WalletComponents.Schemas.ResourceType
export type Resource = WalletComponents.Schemas.Resource
export type Validator = (resource: Resource, veramo: Veramo) => Promise<Error[]>

export class ResourceValidator {
  protected validators: { [key: string]: Validator | undefined }

  constructor () {
    this.validators = {}
    this.initValidators()
  }

  private initValidators (): void {
    this.setValidator('VerifiableCredential', verifiableClaimValidator)
  }

  private setValidator (name: ResourceType, validator: Validator): void {
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
