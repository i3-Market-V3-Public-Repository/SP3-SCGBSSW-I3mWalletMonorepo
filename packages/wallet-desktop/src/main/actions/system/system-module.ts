import { Module } from '../module'
import { closeToast, reset, showToast } from './handlers'

export const systemModule = new Module({
  handlersBuilders: [
    reset,
    closeToast,
    showToast
  ]
})
