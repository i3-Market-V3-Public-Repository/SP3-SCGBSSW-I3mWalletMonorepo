
export type UseState<T> = [
  T,
  React.Dispatch<React.SetStateAction<T>>
]

export function usePresistentState<T> (id: string, defaultValue: T): UseState<T> {
  const localStorageIdentifier = id
  const localStorageState = localStorage.getItem(localStorageIdentifier)
  let initialValue: T
  if (localStorageState === null) {
    initialValue = defaultValue
  } else {
    try {
      initialValue = JSON.parse(localStorageState) as T
    } catch (ex) {
      initialValue = defaultValue
      console.warn('Error parsing localstorage', ex)
    }
  }

  const [state, setState] = React.useState<T>(initialValue)

  return [state, (newStateDispatch) => {
    let newState: T
    if (newStateDispatch instanceof Function) {
      newState = newStateDispatch(state)
    } else {
      newState = newStateDispatch
    }

    localStorage.setItem(localStorageIdentifier, JSON.stringify(newState))
    setState(newState)
  }]
}
