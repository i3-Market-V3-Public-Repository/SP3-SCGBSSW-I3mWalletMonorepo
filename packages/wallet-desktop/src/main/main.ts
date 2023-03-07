import { app, dialog } from 'electron'
import path from 'path'

import { initContext } from '@wallet/lib'

import {
  createLocalsProxy,
  handlePromise,
  Locals,
  LocalsSetter,
  logger,
  MainContext,
  RuntimeManager
} from './internal'
import { createStoreMigrationProxy } from './store/migration'

async function executeRuntime (
  ctx: MainContext,
  locals: Locals,
  setLocals: LocalsSetter
): Promise<void> {
  const runtimeManager = new RuntimeManager(ctx, locals, setLocals)
  runtimeManager.on('ui', async () => {
    locals.toast.show({
      message: 'Test',
      timeout: 0
    })
  })
  await setLocals('runtimeManager', runtimeManager)
  await runtimeManager.run()
}

export default async (argv: string[]): Promise<void> => {
  // This method will be called when Electron has finished
  // initialization and is ready to create browser windows.
  // Some APIs can only be used after this event occurs.
  app.on('ready', () => {
    const singleInstance = app.requestSingleInstanceLock()
    if (!singleInstance) {
      logger.warn('The application is already running')
      dialog.showErrorBox('Cannot start', 'The application is already running. Check your tray.')
      app.quit()
      return
    }

    const ctx = initContext<MainContext>({
      appPath: path.resolve(__dirname, '../../'),
      settingsPath: app.getPath('userData'),
      storeMigrationProxy: createStoreMigrationProxy()
    })
    const [locals, setLocals] = createLocalsProxy(ctx)
    const runtimePromise = executeRuntime(ctx, locals, setLocals)
    handlePromise(locals, runtimePromise)
  })
}
