import procedures from './procedures'

const main = async (): Promise<void> => {
  console.log('Clean destination folder...')
  await procedures.clean()

  console.log('Copy resources...')
  await procedures.copyResources()

  console.log('Watch source files...')
  procedures.buildSource({ watch: true }).catch(err => {
    console.log('Cannot build source', err)
    throw new Error('Cannot build source')
  })

  await procedures.start()

  process.on('SIGINT', () => {
    // Stop all the runing listeners by force!
    // TODO: Maybe try kindly :)
    process.exit()
  })
}

main().catch((err) => {
  if (err instanceof Error) {
    throw err
  } else {
    console.log('Cannot start:', err)
  }
})
