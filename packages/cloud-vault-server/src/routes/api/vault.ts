import { Request, Response, Router } from 'express'
import { HttpError } from 'express-openapi-validator/dist/framework/types'
import { sign as jwtSign } from 'jsonwebtoken'
import { DatabaseError } from 'pg'
import { OpenApiPaths } from '../../../types/openapi'
import { general, jwt, dbConfig } from '../../config'
import { dbFunctions as db } from '../../db'
import { passport, User } from '../../middlewares/passport'
import { vaultEvents } from '../../vault'

export default function (router: Router): void {
  router.use(passport.initialize())
  router.get('/events',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request, res: Response, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const { username } = req.user as User

        const connId = vaultEvents.addConnection(username, res)

        vaultEvents.sendEvent(username, {
          event: 'connected',
          data: {
            timestamp: (await db.getTimestamp(username)) ?? undefined
          }
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
          const error = new HttpError({
            name: 'no storage',
            message: "you haven't upload storage yet",
            path: req.path,
            status: 404
          })
          throw error
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
          const error = new HttpError({
            name: 'no storage',
            message: "you haven't upload storage yet",
            path: req.path,
            status: 404
          })
          throw error
        }
        res.status(200).json(storage)
      } catch (error) {
        return next(error)
      }
    }
  )
  router.delete('/',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const { username } = req.user as User
        await db.deleteStorage(username)
        vaultEvents.sendEvent(username, {
          event: 'storage-deleted',
          data: {}
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
        const { username } = req.user as User
        if (general.nodeEnv === 'development') {
          console.log('VAULT POST', username, req.body)
        }
        const newTimestamp: number = await db.setStorage(username, req.body.ciphertext, req.body.timestamp)
        vaultEvents.sendEvent(username, {
          event: 'storage-updated',
          data: {
            timestamp: newTimestamp
          }
        })
        res.status(201).json({
          timestamp: newTimestamp
        })
      } catch (error) {
        if (error instanceof DatabaseError) {
          switch (error.code) {
            case '22001':
              throw new HttpError({
                name: 'error',
                path: req.path,
                status: 400,
                message: `encrypted storage in base64url cannot be more than ${dbConfig.storageCharLength} long (${dbConfig.storageByteLength} in binary format)`
              })
            default:
              throw new HttpError({
                name: 'error',
                path: req.path,
                status: 400,
                message: 'couldn\'t update storage'
              })
          }
        }
        return next(error)
      }
    }
  )
  router.post('/token',
    async (req: Request<{}, {}, OpenApiPaths.ApiV2VaultToken.Post.RequestBody, {}>, res: Response<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        console.log(req.body)
        const username = req.body.username
        const authkey = req.body.authkey
        const verified = await db.verifyCredentials(username, authkey)
        if (!verified) {
          const error = new HttpError({
            name: 'invalid credentials',
            message: 'invalid username and/or authkey',
            path: req.path,
            status: 404
          })
          throw error
        }
        const token = jwtSign({
          username
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
