import { ArgumentParser } from 'argparse'
import { logger } from './internal'

export interface Args {
  config?: string // Config path
}

export function parseArguments (): Args {
  const parser = new ArgumentParser({
    description: 'Wallet desktop'
  })

  const args = process.argv.slice(3)
  logger.info(`List of arguments: '${args.join(', ')}'`)
  parser.add_argument('-c', '--config', {
    help: 'Select a custom config folder',
    required: false
  })
  return parser.parse_args(args)
}
