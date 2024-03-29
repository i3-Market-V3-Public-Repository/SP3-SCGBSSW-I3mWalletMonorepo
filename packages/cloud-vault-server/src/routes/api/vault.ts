import { Request, Response, Router } from 'express'
import { HttpError } from 'express-openapi-validator/dist/framework/types'
import { sign as jwtSign } from 'jsonwebtoken'
import { DatabaseError } from 'pg'
import { OpenApiPaths } from '../../../types/openapi'
import { general, jwt, dbConfig } from '../../config'
import { dbFunctions as db } from '../../db'
import { passportPromise, User } from '../../middlewares/passport'
import { vaultEvents } from '../../vault/index'

export default async function (router: Router): Promise<void> {
  const passport = await passportPromise
  // router.use(passport.initialize())
  router.post('/token',
    async (req: Request<{}, {}, OpenApiPaths.ApiV2VaultToken.Post.RequestBody, {}>, res: Response<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = req.body.username
        const authkey = req.body.authkey
        const verified = await db.verifyCredentials(username, authkey)
        if (!verified) {
          const error = new HttpError({
            name: 'invalid-credentials',
            message: 'invalid username and/or authkey',
            path: req.baseUrl + req.path,
            status: 404
          })
          throw error
        }
        const token = jwtSign({
          username
        }, jwt.secret, {
          algorithm: jwt.alg,
          expiresIn: jwt.expiresIn
        })
        res.status(200).json({
          token
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.get('/events',
    passport.authenticate('jwtBearer', { session: false }),
    async (req: Request, res: Response, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      const { username } = req.user as User
      try {
        const connId = vaultEvents.addConnection(username, res)
        const timestamp = (await db.getTimestamp(username)) ?? undefined
        vaultEvents.sendEvent(username, {
          event: 'connected',
          data: {
            timestamp
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
            name: 'no-storage',
            message: "you haven't upload storage yet",
            path: req.baseUrl + req.path,
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
            name: 'no-storage',
            message: "you haven't upload storage yet",
            path: req.baseUrl + req.path,
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
        await db.deleteStorageByUsername(username)
        vaultEvents.sendEvent(username, {
          event: 'storage-deleted',
          data: {}
        })
        res.status(204).end()
      } catch (error) {
        if (error instanceof Error && error.message === 'not-registered') {
          return next(new HttpError({
            name: 'not-registered',
            path: req.baseUrl + req.path,
            status: 404
          }))
        }
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
              return next(new HttpError({
                name: 'quota-exceeded',
                path: req.path,
                status: 400,
                message: `encrypted storage in base64url cannot be more than ${dbConfig.storageCharLength} long (${dbConfig.storageByteLength} in binary format)`
              }))
            default:
              return next(new HttpError({
                name: 'error',
                path: req.baseUrl + req.path,
                status: 400,
                message: 'couldn\'t update storage'
              }))
          }
        } else if (error instanceof Error && (error.message === 'invalid-timestamp' || error.message === 'not-registered')) {
          return next(new HttpError({
            name: error.message,
            path: req.baseUrl + req.path,
            status: 400
          }))
        }
        return next(error)
      }
    }
  )
}
