import * as path from 'path'
import { MainContext } from '@wallet/main/internal'

interface Paths {
  publicConfig: string
}

export const paths = (ctx: MainContext): Paths => ({
  publicConfig: path.join(ctx.args.config, 'config.json')
})
