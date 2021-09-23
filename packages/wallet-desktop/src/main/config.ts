import * as fs from 'fs'
import * as path from 'path'

type ConvertFunction<T> = (value: string) => T

class Config {
  protected defaults: {[key: string]: string | undefined }
  protected _ngrokUri?: string
  protected _host?: string

  constructor () {
    this.defaults = {
      NODE_ENV: 'development'
    }
  }

  // Conversion functions
  protected fromBoolean: ConvertFunction<boolean> = (v) => v.toLocaleLowerCase() === '1'
  protected fromArray: ConvertFunction<string[]> = (v) => v.split(',')
  protected fromInteger: ConvertFunction<number> = parseInt
  protected fromImport: <T>(v: string) => T = (v) => {
    // TODO: Only relative path supported
    const file = path.join(__dirname, '../', v)
    if (fs.existsSync(file)) {
      return require(file)
    } else {
      return undefined
    }
  }

  /**
   * Gets a configuration property comming from os environment or the
   * provided default configuration json file and casts the value.
   *
   * @param name Name of the property to get
   * @param convert Function to cast the value
   * @returns Return the property as string
   */
  get (name: string): string
  get<T>(name: string, convert: (value: string) => T): T
  get<T = string>(name: string, convert?: ConvertFunction<T>): T {
    const value = process.env[name] ?? this.defaults[name] ?? ''
    if (convert == null) {
      return value as unknown as T
    }

    return convert(value)
  }

  /**
   * @property Is production environment
   */
  get isProd (): boolean {
    return this.get('NODE_ENV', (v) => v === 'production')
  }

  /**
    * @property Server port
    */
  get port (): number {
    return 8000
  }
}

export const config = new Config()
