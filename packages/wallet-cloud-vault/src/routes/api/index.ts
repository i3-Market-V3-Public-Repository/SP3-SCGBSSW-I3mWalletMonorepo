import { Router } from 'express'
import publicJwk from './public-key'

const router = Router()

export default async (): Promise<Router> => {
  publicJwk(router)

  return router
}
