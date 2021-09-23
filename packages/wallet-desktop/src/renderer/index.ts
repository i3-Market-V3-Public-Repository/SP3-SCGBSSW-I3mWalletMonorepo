import main from './renderer'
import './index.scss'

function initWindow (window: any): void {
  if (window.require !== undefined) {
    window.electron = require('electron')
  }
}
initWindow(window)

main((window as any).windowArgs)
