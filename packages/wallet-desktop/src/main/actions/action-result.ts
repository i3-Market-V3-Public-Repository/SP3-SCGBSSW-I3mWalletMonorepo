export interface ActionResult<T = any> {
  response: T
  status?: number
}
