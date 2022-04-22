
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
    initialValue = JSON.parse(localStorageState) as T
  }

  const [state, setState] = React.useState<T>(initialValue)

  return [state, (newState) => {
    localStorage.setItem(localStorageIdentifier, JSON.stringify(newState))
    setState(newState)
  }]
}
