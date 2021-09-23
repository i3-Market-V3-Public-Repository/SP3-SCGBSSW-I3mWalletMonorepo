import { Observable } from 'rxjs'
import { filter } from 'rxjs/operators'

export interface TypedObject<S extends string = string> {
  type: S
}

export type WithType<T extends TypedObject, S extends string> = TypedObject<S> & T
export type ObservableWithType<T extends TypedObject, S extends string> = Observable<WithType<T, S>>

export const withType = <T extends TypedObject, S extends T['type']>(
  type: S
) => (obs$: Observable<T>): ObservableWithType<T, S> => {
  return obs$.pipe(filter((typedObject) => typedObject.type === type)) as ObservableWithType<T, S>
}
