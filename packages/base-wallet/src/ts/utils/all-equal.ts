import _ from 'lodash'

export function allEqual (arr: any[]): boolean {
  return arr.every(v => _.isEqual(v, arr[0]))
}
