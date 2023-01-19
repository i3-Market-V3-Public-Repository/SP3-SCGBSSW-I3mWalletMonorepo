import { randomUUID } from 'crypto'
import { Response } from 'express'
import { OpenApiComponents } from '../../types/openapi'
import _ from 'lodash'

interface ConnectionToUsernameMap {
  [connId: string]: string // The connection ID maps to the username
}

interface VaultConnection {
  connId: string
  response: Response
}

interface VaultClient {
  connections: VaultConnection[] // all the express responses for all the connections by this username
}

interface VaultClients {
  [username: string]: VaultClient
}

export const VAULT_MANAGER_MSG_CODES = {
  STORAGE_UPDATED: 0,
  STORAGE_DELETED: 1
}

export interface WELLCOME_MSG {
  code: 0
  timestamp: OpenApiComponents.Schemas.Timestamp['timestamp']
}

export interface UPDATE_MSG {
  code: 1
  timestamp: OpenApiComponents.Schemas.Timestamp['timestamp']
}

export interface DELETE_MSG {
  code: 2
}

const headers = {
  'Content-Type': 'text/event-stream',
  Connection: 'keep-alive',
  'Cache-Control': 'no-cache'
}

class VaultEventManager {
  private clients: VaultClients
  private connectionToUsernameMap: ConnectionToUsernameMap

  constructor () {
    this.clients = {}
    this.connectionToUsernameMap = {}
  }

  addConnection (username: string, response: Response): string {
    const connId = randomUUID() // create unique ID for this connection
    this.connectionToUsernameMap[connId] = username

    const connection: VaultConnection = {
      connId,
      response
    }

    if (username in this.clients) {
      this.clients[username].connections.push(connection)
    } else {
      this.clients[username] = { connections: [connection] }
    }

    response.writeHead(200, headers) // Headers are sent in the first connection

    console.log(`[${username}]: new connection open (${connId})`)
    return connId
  }

  closeConnection (connId: string): void {
    const username = this.connectionToUsernameMap[connId]
    const connections = this.clients[username].connections
    _.remove(connections, function (connection) {
      return connection.connId === connId
    })
    if (connections.length === 0) {
      delete this.clients[username] // eslint-disable-line @typescript-eslint/no-dynamic-delete
      delete this.connectionToUsernameMap[connId] // eslint-disable-line @typescript-eslint/no-dynamic-delete
    }
    console.log(`[${username}]: connection closed (${connId})`)
  }

  sendEvent (to: string, event: WELLCOME_MSG | UPDATE_MSG | DELETE_MSG): void {
    if (!(to in this.clients)) {
      throw new Error("Can't send a message to a user that is not connected")
    }
    this.clients[to].connections.forEach(({ response }) => {
      const msg = `data: ${JSON.stringify(event)}\n\n`
      response.write(msg)
    })
  }
}

export const vaultEvents = new VaultEventManager()
