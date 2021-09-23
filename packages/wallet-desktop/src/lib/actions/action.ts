
export interface Action<T extends string = any, P = any> {
  type: T
  payload: P
}
