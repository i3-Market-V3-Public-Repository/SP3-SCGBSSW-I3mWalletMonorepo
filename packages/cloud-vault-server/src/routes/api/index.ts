import { Router } from 'express'
import registration from './registration'
import vault from './vault'

const router = Router()
const registrationRouter = Router({ mergeParams: true })
const vaultRouter = Router({ mergeParams: true })
export default async (): Promise<Router> => {
  registration(registrationRouter)
  vault(vaultRouter)
  router.use('/registration', registrationRouter)
  router.use('/vault', vaultRouter)
  return router
}
