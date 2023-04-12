import { Router } from 'express'
import registration from './registration'
import vault from './vault'
import { passportPromise } from '../../middlewares/passport'

const router = Router()
const registrationRouter = Router({ mergeParams: true })
const vaultRouter = Router({ mergeParams: true })

export default async (): Promise<Router> => {
  const passport = await passportPromise
  router.use(passport.initialize())

  const registrationSubPrefix = '/registration'
  await registration(registrationRouter)
  router.use(registrationSubPrefix, registrationRouter)

  const vaultSubPrefix = '/vault'
  await vault(vaultRouter)
  router.use(vaultSubPrefix, vaultRouter)

  return router
}
