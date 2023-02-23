import { SelectOptions } from '@i3m/base-wallet'

type ValueTransform<T, G extends any[]> = (...args: G) => T
type ValueCompare<T> = (a?: T, b?: T) => boolean

export class SelectBuilder<T, G extends any[]> {
  values: SelectOptions<T>['values']

  constructor (
    protected valueTransform: ValueTransform<T, G>,
    public compare: ValueCompare<T>,
    public getText: SelectOptions<T>['getText'],
    public getContext: SelectOptions<T>['getContext']
  ) {
    this.values = []
  }

  public add (...args: G): T {
    const value = this.valueTransform(...args)
    this.values.push(value)

    return value
  }
}
