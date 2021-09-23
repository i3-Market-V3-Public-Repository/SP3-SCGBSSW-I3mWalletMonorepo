import Debug from 'debug'

import {
  Dialog,
  DialogResponse,
  TextOptions,
  ConfirmationOptions,
  SelectOptions,
  FormOptions
} from '../app'

const debug = Debug('base-wallet:TestDialog')

interface Values {
  text: string | undefined
  confirmation: boolean | undefined
  selectMap: <T>(values: T[]) => T | undefined
}

export class TestDialog implements Dialog {
  // Value management
  private readonly valuesStack: Values[] = [{
    text: 'With love for my caller',
    confirmation: true,
    selectMap (values) {
      if (values.length > 0) {
        return values[0]
      }
      return undefined
    }
  }]

  public get values (): Values {
    return this.valuesStack[this.valuesStack.length - 1]
  }

  async setValues (values: Partial<Values>, cb: () => Promise<void>): Promise<void> {
    this.valuesStack.push(Object.assign({}, this.values, values))
    await cb()
    this.valuesStack.pop()
  }

  // Dialog methods
  async text (options: TextOptions): DialogResponse<string> {
    debug('Returning a dummy text:', this.values.text)
    return this.values.text
  }

  async confirmation (options: ConfirmationOptions): DialogResponse<boolean> {
    debug('Ask for user confirmation:', this.values.confirmation)
    return this.values.confirmation
  }

  async select<T> (options: SelectOptions<T>): DialogResponse<T> {
    const value = this.values.selectMap(options.values)
    debug('Pick item ', value, ' from ', options.values)
    return value
  }

  async authenticate (): DialogResponse<boolean> {
    throw new Error('Method not implemented.')
  }

  async form<T> (options: FormOptions<T>): DialogResponse<T> {
    throw new Error('Method not implemented.')
  }
}
