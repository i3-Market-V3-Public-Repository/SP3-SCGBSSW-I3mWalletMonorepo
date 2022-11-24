import { Module } from '../module'
import { reset } from './reset.handler'
import { closeToast } from './close-toast.handler'
import { showToast } from './show-toast.handler'

export const systemModule = new Module({
  handlersBuilders: [
    reset,
    closeToast,
    showToast,
  ]
})
