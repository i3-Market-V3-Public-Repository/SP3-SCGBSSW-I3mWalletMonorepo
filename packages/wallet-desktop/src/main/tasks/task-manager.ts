import { TaskDescription, WalletTaskTypes } from '@wallet/lib'
import { Locals, logger, MainContext } from '@wallet/main/internal'

import { AddTaskMethod, FinishTaskMethod, LabeledTaskHandlerImpl, ProgressTaskHandlerImpl, TaskHandlerFor, TaskMethods, UpdateTaskMethod } from './handlers'

export class TaskManager implements TaskMethods {
  static async initialize (ctx: MainContext, locals: Locals): Promise<TaskManager> {
    return new TaskManager(locals)
  }

  constructor (protected locals: Locals) {}

  addTask: AddTaskMethod = (task) => {
    this.locals.sharedMemoryManager.update((mem) => ({
      ...mem,
      tasks: [
        ...mem.tasks,
        task
      ]
    }))
  }

  finishTask: FinishTaskMethod = (task) => {
    this.locals.sharedMemoryManager.update((mem) => ({
      ...mem,
      tasks: mem.tasks.filter((memTask) => memTask.id !== task.id)
    }))
  }

  updateTask: UpdateTaskMethod = (task) => {
    this.locals.sharedMemoryManager.update((mem) => ({
      ...mem,
      tasks: mem.tasks.map((memTask) => memTask.id === task.id ? task : memTask)
    }))
  }

  async createTask <T extends WalletTaskTypes, R>(type: T, description: TaskDescription, handler: (task: TaskHandlerFor<T>) => Promise<R>): Promise<R> {
    let taskHandler: TaskHandlerFor<T>
    const hrstart = process.hrtime()
    // TODO: Fix this anys...
    if (type === 'labeled') {
      taskHandler = new LabeledTaskHandlerImpl(this, description) as any
    } else if (type === 'progress') {
      taskHandler = new ProgressTaskHandlerImpl(this, description) as any
    } else {
      throw new Error('unknown task type')
    }

    let result
    try {
      logger.debug(`[title=${description.title},id=${taskHandler.id}] Task started!`)
      this.addTask(taskHandler.task)
      result = await handler(taskHandler)
    } finally {
      const hrend = process.hrtime(hrstart)
      logger.debug(`[title=${description.title},id=${taskHandler.id}] Task ended: ${hrend[0]}s ${hrend[1] / 1000000}ms`)
      this.finishTask(taskHandler.task)
    }
    return result
  }
}
