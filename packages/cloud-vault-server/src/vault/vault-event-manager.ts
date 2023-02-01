import { Response } from 'express'
import _ from 'lodash'
import { randomUUID } from 'node:crypto'
import { OpenApiComponents } from '../../types/openapi'

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

export interface ConnectedEvent {
  event: 'connected'
  data: {
    timestamp?: OpenApiComponents.Schemas.Timestamp['timestamp']
  }
}

export interface StorageUpdatedEvent {
  event: 'storage-updated'
  data: {
    timestamp: OpenApiComponents.Schemas.Timestamp['timestamp']
  }
}

export interface StorageDeletedEvent {
  event: 'storage-deleted'
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

  sendEvent (username: string, event: ConnectedEvent | StorageUpdatedEvent | StorageDeletedEvent): void {
    if ((username in this.clients)) {
      this.clients[username].connections.forEach(({ response }) => {
        response.write(`event: ${event.event}\n`)
        response.write(`data: ${JSON.stringify(event.data)}\n\n`)
      })
    }
  }
}

export const vaultEvents = new VaultEventManager()
