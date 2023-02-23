
export interface TaskDescription {
  readonly title: string
  readonly freezing?: boolean
  details?: string
}

export interface BaseTask<T extends string> {
  readonly type: T
  id: string
  description: TaskDescription
}

export interface ProgressTask extends BaseTask<'progress'> {
  progress: number
}

export interface LabeledTask extends BaseTask<'labeled'> {

}

export type WalletTask = ProgressTask | LabeledTask
export type WalletTaskTypes = WalletTask['type']
export type WalletTaskFor<T extends WalletTaskTypes> = WalletTask & BaseTask<T>
