import { Locals } from '@wallet/main/internal'

type Handler<T> = (opts: T, locals: Locals) => Promise<void>

export interface FeatureHandler<T> {
  name: string
  start?: Handler<T>
  stop?: Handler<T>
}
