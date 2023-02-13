import { config } from '@fortawesome/fontawesome-svg-core'
import { WindowArgs } from '@wallet/lib'
import Windows from './windows'
import { SharedMemoryProvider } from './communication'

const configFontAwesome = (): void => {
  config.autoAddCss = false
}

export default (windowArgs: WindowArgs): void => {
  // if (process.env.NODE_ENV === 'development') {
  //   require('electron-connect').client.create() // eslint-disable-line
  // }

  // Config fontawesome
  configFontAwesome()

  const root = document.getElementById('root')
  const app = (
    <SharedMemoryProvider>
      {
        windowArgs.name === 'Main'
          ? <Windows.Main {...windowArgs} />
          : <div>View not found</div>
      }
    </SharedMemoryProvider>
  )
  ReactDOM.render(app, root)
}
