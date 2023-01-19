import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../../types/openapi'
import { vaultEvents } from '../../vault'

export default function (router: Router): void {
  router.get('/events',
    async (req: Request, res: Response, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const username = 'username' // TO-DO get unique username from token

        const connId = vaultEvents.addConnection(username, res)

        vaultEvents.sendEvent(username, {
          code: 0,
          timestamp: Date.now() // TODO. Get timestamp of last time the storage was updated
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
        res.json({
          timestamp: Date.now()
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.get('/',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Vault.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        res.status(200).json({
          jwe: 'RraFbEXzRKeb6-LVOS1ejNKKR7CS34_eGvQC9luVpvBUxvb5Ul7SMnS3_g-BIrTrhiK0AlMdCIuCJoMQd2SISHY.As9nW9zmGHUgwKikL8m-IfoyTWHmlAAUYfBom14g_GGH940vyxXiXulpSs8uSJNeP8-DquuqozZnGFSgsj9tnxS.1W1FkvVm6ZD0ZguaQHmoQ96zDODBgLMbqCPhFqGLNwf7c.l-F5VoevEez3AiTJDu7oUWnwYgK6Gs9QvrKbxzJOsRKToW2Ha2slS1Dze5OYINaa6rq44Y1tS7m8WDg1s-v.blFNOdNWXFu-xlw-ms_KAFd1WWE6UgGos9ZkHIeSZT8Cu98nU_pk48IC9J5P5y24S0ohU6BaArxl-_dHngPNABE9zA21l',
          timestamp: Date.now()
        })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.delete('/',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        vaultEvents.sendEvent('username', {
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
        console.log(req.body)
        const timestamp = Date.now() // TO-DO
        vaultEvents.sendEvent('username', {
          code: 1, // STORAGE UPDATED MESSAGE
          timestamp
        })
        res.status(201).json({
          timestamp
        })
      } catch (error) {
        return next(error)
      }
    }
  )
}
