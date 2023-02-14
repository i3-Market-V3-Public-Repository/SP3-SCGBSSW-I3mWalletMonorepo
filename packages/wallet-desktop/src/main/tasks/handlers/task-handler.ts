import { WalletTask, WalletTaskFor, WalletTaskTypes } from '@wallet/lib'

export interface IBasicTaskHandler<T extends WalletTask['type']> {
  id: string
  type: T
  task: WalletTaskFor<T>
}

export interface ProgressTaskHandler extends IBasicTaskHandler<'progress'> {
  setProgress: (value: number) => void
}

export interface LabeledTaskHandler extends IBasicTaskHandler<'labeled'> {
  setDetails (label: string): void
}

export type TaskHandlers = ProgressTaskHandler | LabeledTaskHandler
export type TaskHandlerFor<T extends WalletTaskTypes> = TaskHandlers & { type: T }

export type AddTaskMethod = (task: WalletTask) => void
export type UpdateTaskMethod = (task: WalletTask) => void
export type FinishTaskMethod = (task: WalletTask) => void


export interface TaskMethods {
  addTask: AddTaskMethod
  updateTask: UpdateTaskMethod
  finishTask: FinishTaskMethod
}
