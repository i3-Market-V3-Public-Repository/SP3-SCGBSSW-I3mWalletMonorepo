import { Locals } from '@wallet/main/internal'

export const softwareVersion = (locals: Locals): string =>
  `v${locals.packageJson.version}`
