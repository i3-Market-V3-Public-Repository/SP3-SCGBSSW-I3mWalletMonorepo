import http from 'http'
import { Request } from '../request'
import { Response } from '../response'

export class HttpResponse<T extends Request> extends Response<T> {
  constructor (protected res: http.ServerResponse) {
    super()
  }

  async send (request: T): Promise<void> {
    this.res.write(JSON.stringify(request))
    this.res.end()
  }
}
