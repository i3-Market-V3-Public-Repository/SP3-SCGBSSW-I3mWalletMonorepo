import { Request, Response, Router } from 'express'
import type { OpenApiPaths } from '../../../types/openapi'
import { jwksPromise, serverConfig } from '../../config'
import { dbFunctions as db } from '../../db'
import { HttpError } from 'express-openapi-validator/dist/framework/types'
import { passportPromise, RegistrationUser } from '../../middlewares/passport'
import cookieParser from 'cookie-parser'
import { JWK, jweDecrypt } from '@i3m/non-repudiation-library'

export default async function (router: Router): Promise<void> {
  const passport = await passportPromise
  router.use(cookieParser())

  router.get('/public-jwk',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const jwkPair = await jwksPromise
        res.json({ jwk: jwkPair.publicJwk })
      } catch (error: any) {
        return next(error)
      }
    }
  )

  router.get('/register/:data',
    (req: Request<OpenApiPaths.ApiV2RegistrationRegister$Data.Get.PathParameters, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2RegistrationRegister$Data.Get.Responses.$302>) => {
      res.cookie('reg-data', req.params.data, { httpOnly: true })
        .cookie('orig', 'register', { httpOnly: true })
        .redirect(serverConfig.publicUrl + req.baseUrl + '/login')
    }
  )

  router.get('/deregister',
    (req: Request, res: Response<OpenApiPaths.ApiV2RegistrationDeregister.Get.Responses.$302>) => {
      res.cookie('orig', 'deregister', { httpOnly: true })
        .redirect(serverConfig.publicUrl + req.baseUrl + '/login')
    }
  )

  router.get('/login', passport.authenticate('oidc', { scope: 'openid vc vc:provider vc:consumer' }))

  router.get('/cb', passport.authenticate('oidc', { session: false }),
    async function (req: Request, res: Response<OpenApiPaths.ApiV2RegistrationCb.Get.Responses.$201 | OpenApiPaths.ApiV2RegistrationCb.Get.Responses.$204>, next) { // eslint-disable-line @typescript-eslint/no-misused-promises
      const orig = req.cookies.orig
      const regUser = req.user as RegistrationUser
      res.clearCookie('reg-data').clearCookie('orig')
      switch (orig) {
        case 'register': {
          const regData = req.cookies['reg-data']

          const { username, authkey, did } = await decodeRegData(regData)
          if (req.user === undefined) {
            throw new Error('Passport authentication error')
          }
          if (regUser.did !== did) {
            const err = new HttpError({
              status: 401,
              name: 'unauthorized',
              message: 'authenticated did does not match the one that initiated the flow',
              path: req.baseUrl + req.path
            })
            return next(err)
          }
          try {
            await db.registerUser(did, username, authkey)
            res.status(201).json({
              status: 'created',
              username
            })
          } catch (error) {
            if (error !== null && typeof error === 'object' && 'code' in error && error.code === '23505') {
              const err = new HttpError({
                status: 400,
                message: 'user already registered',
                name: 'already-registered',
                path: req.baseUrl + req.path
              })
              return next(err)
            }
            return next(error)
          }
          break
        }
        case 'deregister': {
          await db.deleteStorageByDid(regUser.did).catch((err) => {
            if (err instanceof Error && err.message === 'not-registered') {
              const err = new HttpError({
                status: 404,
                message: 'this identity (DID) is not registered',
                name: 'not-registered',
                errors: [],
                path: req.baseUrl + req.path
              })
              return next(err)
            }
            return next(err)
          })
          res.status(204).end()
          break
        }
        default: {
          const err = new HttpError({
            status: 400,
            message: 'you should not reach this enpoint directly',
            name: 'no-oidc-flow',
            path: req.baseUrl + req.path
          })
          return next(err)
        }
      }
    }
  )
}

async function decodeRegData (regData: string): Promise<{ username: string, authkey: string, did: string }> {
  const jwkPair = await jwksPromise
  const { plaintext } = await jweDecrypt(regData, jwkPair.privateJwk as JWK)
  const payload = JSON.parse(Buffer.from(plaintext).toString('utf-8'))
  if (!('username' in payload) || !('authkey' in payload) || !('did' in payload)) {
    throw new Error('invalid data for registration')
  }
  return { username: payload.username, authkey: payload.authkey, did: payload.did }
}
