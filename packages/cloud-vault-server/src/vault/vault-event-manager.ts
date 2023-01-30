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

export interface CONNECTED_EVENT {
  type: 'connected'
  data: {
    timestamp?: OpenApiComponents.Schemas.Timestamp['timestamp']
  }
}

export interface STORAGE_UPDATED_EVENT {
  type: 'storage-updated'
  data: {
    timestamp: OpenApiComponents.Schemas.Timestamp['timestamp']
  }
}

export interface STORAGE_DELETED_EVENT {
  type: 'storage-deleted'
  data: {}
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

  sendEvent (to: string, event: CONNECTED_EVENT | STORAGE_UPDATED_EVENT | STORAGE_DELETED_EVENT): void {
    if ((to in this.clients)) {
      this.clients[to].connections.forEach(({ response }) => {
        response.write(`type: ${event.type}\n`)
        response.write(`data: ${JSON.stringify(event.data)}\n\n`)
      })
    }
  }
}

export const vaultEvents = new VaultEventManager()
