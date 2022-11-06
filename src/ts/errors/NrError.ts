import { NrErrorName } from '../types'

export class NrError extends Error {
  nrErrors: NrErrorName[]

  constructor (error: any, nrErrors: NrErrorName[]) {
    super(error)
    if (error instanceof NrError) {
      this.nrErrors = error.nrErrors
      this.add(...nrErrors)
    } else {
      this.nrErrors = nrErrors
    }
  }

  add (...nrErrors: NrErrorName[]): void {
    const errors = this.nrErrors.concat(nrErrors)
    this.nrErrors = [...(new Set(errors))]
  }
}
