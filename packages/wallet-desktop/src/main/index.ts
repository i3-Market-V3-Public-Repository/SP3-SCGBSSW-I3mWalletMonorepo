// Before any code is executed, add root path!
import moduleAlias from 'module-alias'
import { join } from 'path'
moduleAlias.addAlias('@wallet', join(__dirname, '/../'))

// NOTE: This line MUST be after added the alias!
import main from './main' // eslint-disable-line
main(process.argv).catch(err => {
  if (err instanceof Error) {
    console.error('Error: ', err.message, err.stack)
    console.error(err)
  } else {
    console.error('Cannot start:', err)
  }
})
