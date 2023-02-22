import { Module } from '../module'
import { startCloudSync } from './start-cloud-sync.handler'
import { stopCloudSync } from './stop-cloud-sync.handler'
import { registerCloud } from './register-cloud.handler'
import { logoutCloud } from './logout-cloud.handler'
import { loginCloud } from './login-cloud.handler'

export const cloudModule = new Module({
  handlersBuilders: [
    startCloudSync,
    stopCloudSync,
    registerCloud,
    logoutCloud,
    loginCloud
  ]
})
