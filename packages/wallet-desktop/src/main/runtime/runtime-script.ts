import { Locals, MainContext } from '@wallet/main/internal'

export type RuntimeScript = (ctx: MainContext, locals: Locals) => Promise<void>
