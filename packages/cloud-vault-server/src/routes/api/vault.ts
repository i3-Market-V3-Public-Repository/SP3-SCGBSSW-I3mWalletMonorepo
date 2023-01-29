import { Request, Response, Router } from 'express'
import { sign as jwtSign } from 'jsonwebtoken'
import { OpenApiPaths } from '../../../types/openapi'
import { general, jwt } from '../../config'
import { dbFunctions as db } from '../../db'
import { vaultEvents } from '../../vault'
import { passport, User } from '../../middlewares/passport'

export default function (router: Router): void {
  router.use(passport.initialize())
  router.get('/events',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request, res: Response, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = (req.user as User).username

        const connId = vaultEvents.addConnection(username, res)

        vaultEvents.sendEvent(username, {
          code: 0,
          timestamp: (await db.getTimestamp(username)) ?? undefined
        })

        req.on('close', () => {
          vaultEvents.closeConnection(connId)
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.get('/timestamp',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2VaultTimestamp.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = (req.user as User).username
        const timestamp = await db.getTimestamp(username)
        if (timestamp === null) {
          throw new Error("you haven't upload storage yet")
        }
        res.status(200).json({
          timestamp
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.get('/',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Vault.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = (req.user as User).username
        const storage = await db.getStorage(username)
        if (storage === null) {
          throw new Error(`User ${username} has not uploaded sotrage yet`)
        }
        res.status(200).json({
          jwe: storage.storage,
          timestamp: storage.timestamp
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.delete('/',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = (req.user as User).username
        await db.deleteStorage(username)
        vaultEvents.sendEvent(username, {
          code: 2 // Delete message
        })
        res.status(204).end()
      } catch (error) {
        return next(error)
      }
    }
  )
  router.post('/',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request<{}, {}, OpenApiPaths.ApiV2Vault.Post.RequestBody, {}>, res: Response<OpenApiPaths.ApiV2Vault.Post.Responses.$201>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = (req.user as User).username
        if (general.nodeEnv === 'development') {
          console.log(username, req.body)
        }
        const newTimestamp: number = await db.setStorage(username, req.body.jwe, req.body.timestamp)
        vaultEvents.sendEvent(username, {
          code: 1, // STORAGE UPDATED MESSAGE
          timestamp: newTimestamp
        })
        res.status(201).json({
          timestamp: newTimestamp
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.post('/auth',
    async (req: Request<{}, {}, OpenApiPaths.ApiV2VaultAuth.Post.RequestBody, {}>, res: Response<OpenApiPaths.ApiV2VaultAuth.Post.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        console.log(req.body)
        const username = req.body.username
        const password = req.body.authkey
        await db.verifyCredentials(username, password)
        const token = jwtSign({
          username,
          password
        }, jwt.secret, {
          algorithm: jwt.alg
        })
        res.status(200).json({
          token
        })
      } catch (error) {
        return next(error)
      }
    }
  )
}
