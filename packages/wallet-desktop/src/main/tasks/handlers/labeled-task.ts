import { LabeledTask, TaskDescription } from '@wallet/lib'
import { v4 as uuid } from 'uuid'

import { LabeledTaskHandler, TaskMethods } from './task-handler'

export class LabeledTaskHandlerImpl implements LabeledTaskHandler {
  id: string
  type: 'labeled' = 'labeled'

  constructor (protected methods: TaskMethods, public description: TaskDescription) {
    this.id = uuid()
  }

  get task (): LabeledTask {
    return {
      id: this.id,
      description: this.description,
      type: this.type
    }
  }

  setDetails (label: string): this {
    this.description.details = label

    return this
  }

  setFreezing (freezing: boolean): this {
    this.description.freezing = freezing
    return this
  }

  update (): this {
    this.methods.updateTask(this.task)
    return this
  }
}
