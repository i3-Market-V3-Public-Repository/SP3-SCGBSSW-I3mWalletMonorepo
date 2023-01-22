import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../../types/openapi'
import { vaultEvents } from '../../vault'
import { db } from '../../db'

export default function (router: Router): void {
  router.get('/events',
    async (req: Request, res: Response, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = 'username' // TO-DO get unique username from token

        const connId = vaultEvents.addConnection(username, res)

        vaultEvents.sendEvent(username, {
          code: 0,
          timestamp: (await db.getTimestamp(username)).valueOf()
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
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2VaultTimestamp.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = 'username' // TO-DO get unique username from token
        res.json({
          timestamp: (await db.getTimestamp(username)).valueOf()
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.get('/',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Vault.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = 'username' // TO-DO get unique username from token
        const storage = await db.getStorage(username)
        res.status(200).json({
          jwe: storage.storage ?? '',
          timestamp: storage.timestamp.valueOf()
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.delete('/',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = 'username' // TO-DO get unique username from token
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
    async (req: Request<{}, {}, OpenApiPaths.ApiV2Vault.Post.RequestBody, {}>, res: Response<OpenApiPaths.ApiV2Vault.Post.Responses.$201>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = 'username' // TO-DO get unique username from token
        console.log(req.body)
        let timestamp = (await db.getTimestamp(username)).valueOf()
        if (req.body.timestamp === timestamp) {
          timestamp = req.body.timestamp
          await db.setStorage(username, req.body.jwe)
          vaultEvents.sendEvent(username, {
            code: 1, // STORAGE UPDATED MESSAGE
            timestamp
          })
        }
        res.status(201).json({
          timestamp
        })
      } catch (error) {
        return next(error)
      }
    }
  )
}
