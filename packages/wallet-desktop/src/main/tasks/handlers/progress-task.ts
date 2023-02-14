import { ProgressTask, TaskDescription } from '@wallet/lib'
import { v4 as uuid } from 'uuid'

import { ProgressTaskHandler, TaskMethods } from './task-handler'

export class ProgressTaskHandlerImpl implements ProgressTaskHandler {
  id: string
  type: 'progress' = 'progress'
  protected progress = 0

  constructor (protected methods: TaskMethods, public description: TaskDescription) {
    this.id = uuid()
  }

  get task (): ProgressTask {
    return {
      id: this.id,
      progress: this.progress,
      description: this.description,
      type: this.type
    }
  }

  setProgress (value: number): void {
    this.progress = value
    if (value >= 100) {

    }
  }
}
