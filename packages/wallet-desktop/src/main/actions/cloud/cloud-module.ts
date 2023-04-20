import { Module } from '../module'
import { loginCloud, logoutCloud, registerCloud, reloginCloud, restartClient, deleteCloud, syncCloud, stopCloud } from './handlers'
import { uploadStoresEpic } from './epics'

export const cloudModule = new Module({
  handlersBuilders: [
    deleteCloud,
    registerCloud,
    logoutCloud,
    loginCloud,
    reloginCloud,
    syncCloud,
    restartClient,
    stopCloud
  ],
  epics: [
    uploadStoresEpic
  ]
})
