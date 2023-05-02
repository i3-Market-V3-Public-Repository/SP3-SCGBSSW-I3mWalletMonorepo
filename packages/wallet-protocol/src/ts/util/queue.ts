
export class Queue<T> {
  protected _values: T[]
  protected _first: number
  protected _length: number

  constructor (readonly maxLength: number) {
    this._values = new Array(maxLength)
    this._first = 0
    this._length = 0
  }

  get length (): number {
    return this._length
  }

  push (value: T): void {
    this._values[this.lastIndex] = value
    if (this.length >= this.maxLength) {
      this._first = (this._first + 1) % this.maxLength
    } else {
      this._length++
    }
  }

  pop (): T | undefined {
    if (this.length > 0) {
      const v = this._values[this._first]
      this._first = (this._first + 1) % this.maxLength
      this._length--

      return v
    }
  }

  private get lastIndex (): number {
    return (this._first + this._length) % this.maxLength
  }

  get last (): T | undefined {
    return this._values[this.lastIndex]
  }
}
