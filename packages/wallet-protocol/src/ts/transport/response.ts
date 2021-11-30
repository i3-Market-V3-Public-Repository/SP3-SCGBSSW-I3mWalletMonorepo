import { Request } from './request'

export abstract class Response<T extends Request = Request> {
  abstract send (request: T): Promise<void>
}
