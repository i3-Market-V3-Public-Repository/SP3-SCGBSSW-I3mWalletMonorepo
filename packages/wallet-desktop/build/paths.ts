import * as path from 'path'

const root = path.resolve(__dirname, '..')

export default {
  root,
  dist: path.resolve(root, 'dist'),
  src: path.resolve(root, 'src'),
  res: path.resolve(root, 'res'),
  build: path.resolve(root, 'build')
}
