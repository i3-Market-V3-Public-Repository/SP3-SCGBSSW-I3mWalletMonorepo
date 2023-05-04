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

  setProgress (value: number): this {
    this.progress = value
    if (value >= 100) {
      throw new Error('Not implemented yet!')
    }
    return this
  }

  update (): this {
    this.methods.updateTask(this.task)
    return this
  }
}
