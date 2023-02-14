import { Module } from '../module'
import { startCloudSync } from './start-cloud-sync.handler'
import { stopCloudSync } from './stop-cloud-sync.handler'

export const cloudModule = new Module({
  handlersBuilders: [
    startCloudSync,
    stopCloudSync
  ]
})
