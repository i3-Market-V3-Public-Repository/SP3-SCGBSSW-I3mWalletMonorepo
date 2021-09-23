
type Primitive =
  | bigint
  | boolean
  | null
  | number
  | string
  | symbol
  | undefined

type JSONValue = Primitive | JSONObject | JSONArray

export interface JSONObject {
  [key: string]: JSONValue
}

export interface JSONArray extends Array<JSONValue> { }
