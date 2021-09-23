
export class StartFeatureError extends Error {
  constructor (message: string, public exit = false) {
    super(message)
  }
}
