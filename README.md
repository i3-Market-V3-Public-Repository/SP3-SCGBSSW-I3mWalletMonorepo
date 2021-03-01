[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# @my-scope/my-package-name

The `README.md` file is automatically generated from the `src/README.md` file. EDIT `src/README.md` and rewrite it to your heart's content.

The “Tooling” and “Scripts” sections should be removed, but the rest of sections may be useful for your package readme, and you may just modified them to meet your needs.

This project was bootstrapped with `create-node-browser-module`, which creates a boilerplate already prepared for developing modules for browsers and node.js without any required extra effort.

You should just focus on developing your typescript code in the `src` folder and creating unit testing (mocha+chai) files either in the `test` or the `src` directory, although in the latter case only files ending with `.spec.ts` will be considered as test files.

You can use string variable `IS_BROWSER` to create specific code for native JS or Node. For example:

```typescript
if (IS_BROWSER === 'true') {
  // browser specific code here
} else {
  // node.js specific code here
}
```

## Tooling

- Build: [Rollup](https://rollupjs.org) is used for generating IIFE, ESM and CJS modules with the corresponding Typescript declaration files and sourcemaps in the `dist` directory.
- Coverage: [Nyc-Istanbul](https://github.com/istanbuljs/nyc) is used to track how well your unit-tests exercise your codebase.
- Doc: [TsCode](https://tsdoc.org/) is used for automatically generating the [API docs](./docs/API.md). Consider documenting your code with TsCode for it to be useful.
- Lint: [ts-stamdard](https://github.com/standard/ts-standard) is the chosen linter, although you can easily change it by any other linter (update `scripts.lint` in the `package.json`). If developing with [Visual Studio Code](https://code.visualstudio.com/), consider installing the [Standard-JS extension](https://marketplace.visualstudio.com/items?itemName=chenxsan.vscode-standardjs) and select `ts-standard` as the `Standard:engine` in the extension settings.
- Test: [Mocha](https://mochajs.org/) with [Chai](https://www.chaijs.com/) running both in Node.js and browser (using [puppeteer](https://pptr.dev/)). Test files should be created assuming that Mocha methods and Chai are declared global, so there is no need to import them (see the provided test examples). There is also no need to create separate test files for browser and Node.js, since every file will be tested against both.

## Scripts

- `npm run build`. Runs the linter (`lint`), builds the JS files (`build:js`), builds the `README.md` and the API doc `./docs/API.md` (`docs`), runs the unit tests in browser (`test:browser`), and creates a coverage report of the tests run in Node.js (`coverage`). See the specific scripts for more details.
- `npm run build:js`. Creates your distributable module files (IIFE, ESM and CJS), along with the sourcemap and typescript declaration files in the `dist` directory.
- `npm run clean`. Cleans all the artifacts created by the rest of the script (most likely not needed).
- `npm run coverage`. Runs all the unit tests (`src/**/*.spec.ts` and `test/**/*.ts`) in Node.js and track how well they exercise your codebase. Besides the on-screen summary, a complete report in HTML will be generated in the `coverage` directory.
- `npm run docs`. Generates the `README.md` and the API doc `./docs/API.md`. Some labels in the `src/README.md` file will be automatically replaced in the generated `README.md`:

  - &#123;&#123;PKG_NAME&#125;&#125; is automatically replaced with property `name` in `package.json` file.
  - &#123;&#123;PKG_CAMELCASE&#125;&#125; will be replaced by a came case transformation of the package_name.
  - &#123;&#123;IIFE_BUNDLE&#125;&#125; will point to the IIFE bundle file if using github or gitlab as repository.
  - &#123;&#123;ESM_BUNDLE&#125;&#125; will point to the ESM bundle file if using github or gitlab as repository.
  - It has also some automatically added badges (see the top of this file), that you can remove if desired.

- `npm run lint`. Uses the `ts-standard` linter to fix all the project files. If unconfortable, change the linter for the one of your liking.
- `npm run mocha -- <glob>`. Runs Node.js mocha for the selected tests (use glob pattern).
- `npm run mocha-watch -- <glob>`. Runs Node.js mocha in watch mode (test reexecuted if code changes) for the selected tests (use glob pattern).
- `npm test`. Runs all the unit tests (`src/**/*.spec.ts` and `test/**/*.ts`) in both Node.js and browser (using puppeteer).
- `npm run test:browser`. Runs all the unit tests (`src/**/*.spec.ts` and `test/**/*.ts`) in a browser (using pupppeteer).
- `npm run test:node`. Runs all the unit tests (`src/**/*.spec.ts` and `test/**/*.ts`) in Node.js.
- `npm run watch`. Likely to be the default script during development. Tests are automatically reexecuted whenever a test or source file changes.

## Installation

`@my-scope/my-package-name` can be imported to your project with `npm`:

```bash
npm install @my-scope/my-package-name
```

NPM installation defaults to the ES6 module for browsers and the CJS one for Node.js.

For web browsers, you could also directly download the IIFE bundle or the ESM bundle from the repository.

## Usage examples

Import your module as :

- Node.js

   ```javascript
   const myPackageName = require('@my-scope/my-package-name')
   ... // your code here
   ```

- JavaScript native or TypeScript project (including React and Angular)

   ```javascript
   import * as myPackageName from '@my-scope/my-package-name'
   ... // your code here
   ```

   If you are using Angular, since this library uses node typings, you should also add them to the `angularCompilerOptions` in your `tsconfig.json`:

   ```json
     "angularCompilerOptions": {
       "types": ["node"]
       ...
     }
   ```

- JavaScript native browser ES module

   ```html
   <script type="module">
     import * as myPackageName from 'index.browser.bundle.mod.js'  // Use your actual path to the browser mod bundle, which you can find in the dist directory
     ...  // your code here
   </script>
   ```

- JavaScript native browser IIFE

   ```html
   <head>
     ...
     <script src="index.browser.bundle.iife.js"></script><!-- Use your actual path to the browser iife bundle, which you can find in the dist -->
   </head>
   <body>
     ...
     <script>
       ...  // your code here
     </script>
   </body>
   ```

An example of usage could be:

```javascript
YOUR JAVASCRIPT EXAMPLE CODE HERE
```

## API reference documentation

[Check the API](./docs/API.md)
