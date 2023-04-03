import { ArgumentParser } from 'argparse'
import { app } from 'electron'
import path from 'path'

import { logger } from './internal'

export interface Args {
  // settingsPath: string
  config: string // Config path
}

export function parseArguments (): Args {
  const parser = new ArgumentParser({
    description: 'Wallet desktop'
  })

  const DEFAULT_ARGS: Args = {
    config: app.getPath('userData'),
  }

  const args = process.argv.slice(1, -1)
  logger.info(`List of arguments: '${process.argv}'`)
  logger.info(`List of arguments: '${args}'`)
  parser.add_argument('-c', '--config', {
    help: 'Select a custom config folder.',
    required: false
  })
  parser.add_argument('-r', {
    help: 'Module to preload (option can be repeated).',
    required: false
  })
  parser.add_argument('--js-flags', {
    help: 'Javascript flags?',
    required: false
  })

  const parsedArgs = parser.parse_args(args)

  return Object.assign(
    {},
    {
      ...parsedArgs,
      config: parsedArgs.config ? path.resolve(parsedArgs.config) : undefined
    },
    DEFAULT_ARGS
  )
}
