
function findArguments (argv: string[]): string | undefined {
  for (const arg of argv) {
    if (arg.startsWith('--args=')) {
      return arg.substring(7)
    }
  }
}

function loadArguments (argv: string[]): void {
  const argumentsString = findArguments(argv)
  if (argumentsString !== undefined) {
    const jsonString = Buffer.from(argumentsString, 'base64').toString('utf8')
    const global: any = window as any
    global.windowArgs = JSON.parse(jsonString)
  }
}

loadArguments(process.argv)
