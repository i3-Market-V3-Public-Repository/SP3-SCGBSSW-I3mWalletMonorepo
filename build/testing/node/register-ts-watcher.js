const ts = require('typescript')
const path = require('path')
const rootDir = path.join(__dirname, '../../../')
const rimraf = require('rimraf')

const formatHost = {
  getCanonicalFileName: path => path,
  getCurrentDirectory: ts.sys.getCurrentDirectory,
  getNewLine: () => ts.sys.newLine
}

function watchMain () {
  // const configPath = ts.findConfigFile(
  //   /*searchPath*/ "./",
  //   ts.sys.fileExists,
  //   "tsconfig.json"
  // );
  const configPath = path.join(rootDir, 'tsconfig.tests.json')
  if (!configPath) {
    throw new Error("Could not find a valid 'tsconfig.tests.json'.")
  }

  // TypeScript can use several different program creation "strategies":
  //  * ts.createEmitAndSemanticDiagnosticsBuilderProgram,
  //  * ts.createSemanticDiagnosticsBuilderProgram
  //  * ts.createAbstractBuilder
  // The first two produce "builder programs". These use an incremental strategy
  // to only re-check and emit files whose contents may have changed, or whose
  // dependencies may have changes which may impact change the result of prior
  // type-check and emit.
  // The last uses an ordinary program which does a full type check after every
  // change.
  // Between `createEmitAndSemanticDiagnosticsBuilderProgram` and
  // `createSemanticDiagnosticsBuilderProgram`, the only difference is emit.
  // For pure type-checking scenarios, or when another tool/process handles emit,
  // using `createSemanticDiagnosticsBuilderProgram` may be more desirable.
  const createProgram = ts.createEmitAndSemanticDiagnosticsBuilderProgram

  // Note that there is another overload for `createWatchCompilerHost` that takes
  // a set of root files.
  const host = ts.createWatchCompilerHost(
    configPath,
    {},
    ts.sys,
    createProgram,
    reportDiagnostic,
    reportWatchStatusChanged
  )

  // You can technically override any given hook on the host, though you probably
  // don't need to.
  // Note that we're assuming `origCreateProgram` and `origPostProgramCreate`
  // doesn't use `this` at all.
  const origCreateProgram = host.createProgram
  host.createProgram = (rootNames, options, host, oldProgram) => {
    return origCreateProgram(rootNames, options, host, oldProgram)
  }
  const origPostProgramCreate = host.afterProgramCreate

  host.afterProgramCreate = program => {
    origPostProgramCreate(program)
  }

  // `createWatchProgram` creates an initial program, watches files, and updates
  // the program over time.
  ts.createWatchProgram(host)
}

function reportDiagnostic (diagnostic) {
  const filePath = path.relative(rootDir, diagnostic.file.fileName)
  console.error(`[Error ${diagnostic.code}]`, filePath, ':', ts.flattenDiagnosticMessageText(diagnostic.messageText, formatHost.getNewLine()))
}

/**
 * Prints a diagnostic every time the watch status changes.
 * This is mainly for messages like "Starting compilation" or "Compilation completed".
 */
function reportWatchStatusChanged (diagnostic) {
  // console.info(ts.formatDiagnostic(diagnostic, formatHost))
}

// Clean .tests on exit
process.on('SIGINT', () => rimraf.sync(path.join(rootDir, '.tests'), { disableGlob: true }))

watchMain()
