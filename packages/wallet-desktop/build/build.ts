import procedures from './procedures'

const main = async (args: string[]): Promise<void> => {
  console.log('Copy resources...')
  await procedures.copyResources()

  console.log('Watch source files...')
  const watch = args[2] === 'watch'
  await procedures.buildSource({ watch })
}

main(process.argv).catch((err) => {
  if (err instanceof Error) {
    throw err
  } else {
    console.log('Cannot build:', err)
  }
})
