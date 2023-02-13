import * as Renderer from 'electron'

declare global {
  export const electron: typeof Renderer
}
