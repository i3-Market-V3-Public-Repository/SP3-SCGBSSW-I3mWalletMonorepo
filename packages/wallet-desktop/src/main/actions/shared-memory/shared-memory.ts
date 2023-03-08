import { Module } from '../module'
import { settingsUpdateEpic } from './epics'

export const sharedMemoryModule = new Module({
  handlersBuilders: [],
  epics: [
    settingsUpdateEpic
  ]
})
