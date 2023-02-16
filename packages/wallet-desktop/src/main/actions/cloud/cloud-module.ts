import { Module } from '../module'
import { startCloudSync } from './start-cloud-sync.handler'
import { stopCloudSync } from './stop-cloud-sync.handler'
import { registerCloud } from './register-cloud.handler'

export const cloudModule = new Module({
  handlersBuilders: [
    startCloudSync,
    stopCloudSync,
    registerCloud
  ]
})
