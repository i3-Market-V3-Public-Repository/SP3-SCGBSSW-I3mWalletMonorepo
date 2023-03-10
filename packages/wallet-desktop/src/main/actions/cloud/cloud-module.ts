import { Module } from '../module'
import { loginCloud, logoutCloud, registerCloud, reloginCloud, startCloudSync, stopCloudSync, syncCloud } from './handlers'
import { uploadStoresEpic } from './epics'

export const cloudModule = new Module({
  handlersBuilders: [
    startCloudSync,
    stopCloudSync,
    registerCloud,
    logoutCloud,
    loginCloud,
    reloginCloud,
    syncCloud
  ],
  epics: [
    uploadStoresEpic
  ]
})
