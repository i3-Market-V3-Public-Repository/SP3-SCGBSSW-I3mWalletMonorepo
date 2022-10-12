"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
var fs_1 = __importDefault(require("fs"));
var path_1 = __importDefault(require("path"));
var wallet_desktop_openapi_1 = __importDefault(require("@i3m/wallet-desktop-openapi"));
var package_json_1 = __importDefault(require("../package.json"));
var rootDir = path_1["default"].join(__dirname, '..');
var srcDir = path_1["default"].join(rootDir, package_json_1["default"].directories.src, 'ts');
function capitalize(input) {
    return input[0].toUpperCase() + input.slice(1);
}
function fixClassName(name) {
    var fixedName = isNaN(Number(name[0])) ? name : "$".concat(name);
    return capitalize(fixedName);
}
var Code = /** @class */ (function () {
    function Code(str) {
        if (str === void 0) { str = ''; }
        this.str = str;
    }
    Code.prototype.prependLine = function (line, tab, tabChar) {
        if (tab === void 0) { tab = 0; }
        if (tabChar === void 0) { tabChar = '  '; }
        var prevStr = this.str;
        var newLine = '';
        if (line !== undefined) {
            newLine = tabChar.repeat(tab) + line;
        }
        this.str = newLine + '\n' + prevStr;
    };
    Code.prototype.writeLine = function (line, tab, tabChar) {
        if (tab === void 0) { tab = 0; }
        if (tabChar === void 0) { tabChar = '  '; }
        if (line !== undefined) {
            this.str += tabChar.repeat(tab) + line;
        }
        this.str += '\n';
    };
    Code.prototype.replace = function (match, code) {
        var replaceText = code === undefined ? '' : code.str;
        this.str = this.str.replace(match, replaceText);
    };
    Code.prototype.save = function (path) {
        fs_1["default"].writeFileSync(path, this.str);
    };
    Code.prototype.print = function () {
        console.log(this.str);
    };
    Code.fromFile = function (path) {
        return new Code(fs_1["default"].readFileSync(path, 'utf-8'));
    };
    Code.fromMethods = function (methods, defaults) {
        var code = new Code();
        for (var _i = 0, methods_1 = methods; _i < methods_1.length; _i++) {
            var partialMethod = methods_1[_i];
            var method = Object.assign({
                tab: 0,
                visibility: '',
                tabChar: '  ',
                name: 'example',
                params: [],
                returnType: 'void'
            }, partialMethod, defaults);
            code.writeLine("".concat(method.visibility !== '' ? "".concat(method.visibility, " ") : '').concat(method.name, " (").concat(method.params.map(function (param) { return "".concat(param.name, ": ").concat(param.type); }).join(', '), "): ").concat(method.returnType), method.tab, method.tabChar);
        }
        return code;
    };
    return Code;
}());
var methodsFromOpenapi = function () {
    // Write methods
    var methods = [];
    Object.entries(wallet_desktop_openapi_1["default"].paths).forEach(function (_a) {
        var path = _a[0], openapiPath = _a[1];
        Object.entries(openapiPath).forEach(function (_a) {
            var method = _a[0], openapiMethod = _a[1];
            // Get method name
            var operationId = openapiMethod.operationId;
            // Build return type
            var operationClass = fixClassName(operationId);
            var returnType = "Promise<".concat(Object.keys(openapiMethod.responses)
                .filter(function (code) { return code !== 'default'; })
                .map(function (code) {
                var codeClass = fixClassName(code);
                return "WalletPaths.".concat(operationClass, ".Responses.").concat(codeClass);
            }).join(' | '), ">");
            // Build params
            var params = [];
            if (openapiMethod.parameters !== undefined) {
                var hasQueryParam = false;
                var hasPathParam = false;
                for (var _i = 0, _b = openapiMethod.parameters; _i < _b.length; _i++) {
                    var param = _b[_i];
                    if (!hasQueryParam && param["in"] === 'query') {
                        hasQueryParam = true;
                        params.push({
                            name: 'queryParameters',
                            type: "WalletPaths.".concat(operationClass, ".QueryParameters")
                        });
                    }
                    if (!hasPathParam && param["in"] === 'path') {
                        hasPathParam = true;
                        params.push({
                            name: 'pathParameters',
                            type: "WalletPaths.".concat(operationClass, ".PathParameters")
                        });
                    }
                    if (hasPathParam && hasQueryParam) {
                        break;
                    }
                }
            }
            if (openapiMethod.requestBody !== undefined) {
                params.push({
                    name: 'requestBody',
                    type: "WalletPaths.".concat(operationClass, ".RequestBody")
                });
            }
            // funcArguments.push('dialog: Dialog')
            methods.push({
                name: operationId,
                params: params,
                returnType: returnType
            });
        });
    });
    return methods;
};
var writeWalletCode = function (methods, dstPath, templatePath, visibility) {
    if (visibility === void 0) { visibility = ''; }
    var code = Code.fromFile(templatePath);
    var methodsCode = Code.fromMethods(methods, {
        visibility: visibility,
        tab: 1
    });
    code.prependLine('/* DO NOT MODIFY THIS FILE */');
    code.replace(/\r/g); // Remove windows CR...
    code.replace(/ *\/\/ *@ts-ignore\n/g);
    code.replace(/ *\/\/ *@wallet-methods\n/g, methodsCode);
    code.save(dstPath);
};
var walletInterfaceGenerator = function () {
    var methods = methodsFromOpenapi();
    // writeWalletCode(methods,
    //   path.join(srcDir, 'wallet/base-wallet.ts'),
    //   path.join(srcDir, 'wallet/base-wallet.template.ts'),
    //   'async')
    writeWalletCode(methods, path_1["default"].join(srcDir, 'wallet/wallet.ts'), path_1["default"].join(srcDir, 'wallet/wallet.template.ts'));
    // writeWalletCode(methods)
};
exports["default"] = walletInterfaceGenerator;
if (require.main === module) {
    walletInterfaceGenerator();
}
