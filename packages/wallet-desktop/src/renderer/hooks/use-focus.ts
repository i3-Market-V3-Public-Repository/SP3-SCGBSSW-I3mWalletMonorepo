
type FocusFunction = () => void
type FocusHook<T> = [React.RefObject<T>, FocusFunction]

export const useFocus = <T extends HTMLElement = HTMLElement>(): FocusHook<T> => {
  const ref = React.useRef<T>(null)
  const focus = (): void => {
    if (ref.current !== null) {
      ref.current.focus()
    }
  }

  return [ref, focus]
}
