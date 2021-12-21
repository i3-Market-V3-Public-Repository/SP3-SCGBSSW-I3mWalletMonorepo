import { Module } from '../module'
import { reset } from './reset.handler'

export const systemModule = new Module({
  handlersBuilders: [
    reset
  ]
})
