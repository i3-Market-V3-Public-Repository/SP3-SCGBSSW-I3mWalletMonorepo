import { Module } from '../module'
import { loginCloud, logoutCloud, registerCloud, reloginCloud, startCloudSync, stopCloudSync, syncCloud } from './handlers'

export const cloudModule = new Module({
  handlersBuilders: [
    startCloudSync,
    stopCloudSync,
    registerCloud,
    logoutCloud,
    loginCloud,
    reloginCloud,
    syncCloud
  ]
})
