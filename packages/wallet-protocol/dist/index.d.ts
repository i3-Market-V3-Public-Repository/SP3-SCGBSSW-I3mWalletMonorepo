/// <reference types="node" />
import http from 'http';

declare const _default: {
    RPC_URL_PATH: ".well-known/wallet-protocol";
    PORT_LENGTH: 12;
    DEFAULT_RANDOM_LENGTH: 36;
    DEFAULT_TIMEOUT: 30000;
    PORT_SPACE: number;
    INITIAL_PORT: 29170;
    NONCE_LENGTH: 128;
    COMMITMENT_LENGTH: 256;
};
//# sourceMappingURL=index.d.ts.map

declare class BaseECDH {
    generateKeys(): Promise<void>;
    getPublicKey(): Promise<string>;
    deriveBits(publicKeyHex: string): Promise<Uint8Array>;
}
type CipherAlgorithms = 'aes-256-gcm';
declare class BaseCipher {
    readonly algorithm: CipherAlgorithms;
    readonly key: Uint8Array;
    constructor(algorithm: CipherAlgorithms, key: Uint8Array);
    encrypt(payload: Uint8Array): Promise<Uint8Array>;
    decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}

declare class Queue<T> {
    readonly maxLength: number;
    protected _values: T[];
    protected _first: number;
    protected _length: number;
    constructor(maxLength: number);
    get length(): number;
    push(value: T): void;
    pop(): T | undefined;
    private get lastIndex();
    get last(): T | undefined;
}

type Resolver<T> = (value: T) => void;
type Rejecter = (reason: any) => void;
declare class Subject<T = unknown> {
    readonly queueLength: number;
    protected queue: Queue<T>;
    protected resolvePending?: Resolver<T>;
    protected rejectPending?: Rejecter;
    constructor(queueLength?: number);
    get promise(): Promise<T>;
    protected createPromise(): Promise<T>;
    next(value: T): void;
    err(reason: any): void;
    finish(): void;
    private unbindPromise;
}

declare class EventEmitter {
    events: Record<string, Function[]>;
    constructor();
    on(event: string, cb: Function): this;
    emit(event: string, ...data: any): boolean;
}

interface Identity {
    name: string;
    url?: string;
}
interface PKEData {
    id: Identity;
    rx: Uint8Array;
    publicKey: string;
}
interface ProtocolPKEData {
    a: PKEData;
    b: PKEData;
    port: number;
    sent: PKEData;
    received: PKEData;
}
interface AuthData {
    cx: Uint8Array;
    nx: Uint8Array;
    r: Uint8Array;
}
interface ProtocolAuthData {
    a: AuthData;
    b: AuthData;
    sent: AuthData;
    received: AuthData;
}

declare class MasterKey {
    readonly port: number;
    readonly from: Identity;
    readonly to: Identity;
    readonly na: Uint8Array;
    readonly nb: Uint8Array;
    protected secret: Uint8Array;
    protected cipher: BaseCipher;
    protected decipher: BaseCipher;
    constructor(port: number, from: Identity, to: Identity, na: Uint8Array, nb: Uint8Array, secret: Uint8Array, encryptKey: Uint8Array, decryptKey: Uint8Array);
    encrypt(message: Uint8Array): Promise<Uint8Array>;
    decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
    toJSON(): any;
    fromHash(): Promise<string>;
    toHash(): Promise<string>;
    static fromSecret(port: number, from: Identity, to: Identity, na: Uint8Array, nb: Uint8Array, secret: Uint8Array): Promise<MasterKey>;
    static fromJSON(data: any): Promise<MasterKey>;
}

declare class Session<T extends Transport> {
    protected transport: T;
    protected masterKey: MasterKey;
    protected code: Uint8Array;
    constructor(transport: T, masterKey: MasterKey, code: Uint8Array);
    send(request: TransportRequest<T>): Promise<TransportResponse<T>>;
    toJSON(): any;
    static fromJSON<T extends Transport>(transport: T, json: any): Promise<Session<T>>;
    static fromJSON<T extends Transport>(transportConstructor: new () => T, json: any): Promise<Session<T>>;
}

declare class WalletProtocol<T extends Transport = Transport> extends EventEmitter {
    transport: T;
    _running: Promise<Session<T>> | undefined;
    constructor(transport: T);
    computeR(ra: Uint8Array, rb: Uint8Array): Promise<Uint8Array>;
    computeNx(): Promise<Uint8Array>;
    computeCx(pkeData: ProtocolPKEData, nx: Uint8Array, r: Uint8Array): Promise<Uint8Array>;
    validateAuthData(fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<void>;
    computeMasterKey(ecdh: BaseECDH, fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<MasterKey>;
    run(): Promise<Session<T>>;
    get isRunning(): boolean;
    finish(): Promise<void>;
    on(event: 'connString', listener: (connString: ConnectionString) => void): this;
    on(event: 'masterKey', listener: (masterKey: MasterKey) => void): this;
    on(event: 'finished', listener: () => void): this;
    emit(event: 'connString', connString: ConnectionString): boolean;
    emit(event: 'masterKey', masterKey: MasterKey): boolean;
    emit(event: 'finished'): boolean;
}

declare class ConnectionString {
    protected buffer: Uint8Array;
    protected l: number;
    constructor(buffer: Uint8Array, l: number);
    toString(): string;
    extractPort(): number;
    extractRb(): Uint8Array;
    static generate(port: number, l: number): Promise<ConnectionString>;
    static fromString(connString: string, l: number): ConnectionString;
}

interface CodeGenerator {
    generate: (masterKey: MasterKey) => Promise<Uint8Array>;
    getMasterKey: (code: Uint8Array) => Promise<MasterKey>;
}
declare const defaultCodeGenerator: CodeGenerator;

declare class WalletProtocolError extends Error {
    readonly httpCode: number;
    readonly parentError?: unknown;
    constructor(message: string, httpCode?: number, parentError?: unknown);
}
declare class InvalidPinError extends WalletProtocolError {
}

interface Transport<Req = any, Res = any> {
    prepare: (protocol: WalletProtocol, publicKey: string) => Promise<PKEData>;
    publicKeyExchange: (protocol: WalletProtocol, pkeData: PKEData) => Promise<ProtocolPKEData>;
    authentication: (protocol: WalletProtocol, authData: AuthData) => Promise<ProtocolAuthData>;
    verification: (protocol: WalletProtocol, masterKey: MasterKey) => Promise<Uint8Array>;
    send: (masterKey: MasterKey, code: Uint8Array, request: Req) => Promise<Res>;
    finish: (protocol: WalletProtocol) => void;
}
type TransportRequest<T> = T extends Transport<infer Req> ? Req : never;
type TransportResponse<T> = T extends Transport<any, infer Res> ? Res : never;
declare abstract class BaseTransport<Req, Res> implements Transport<Req, Res> {
    abstract prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    abstract publicKeyExchange(protocol: WalletProtocol, publicKey: PKEData): Promise<ProtocolPKEData>;
    abstract authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    abstract verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    send(masterKey: MasterKey, code: Uint8Array, req: Req): Promise<Res>;
    finish(protocol: WalletProtocol): void;
}

interface PublicKeyExchangeRequest {
    method: 'publicKeyExchange';
    sender: Identity;
    publicKey: string;
    ra?: string;
}
interface CommitmentRequest {
    method: 'commitment';
    cx: string;
}
interface NonceRevealRequest {
    method: 'nonce';
    nx: string;
}
interface VerificationRequest {
    method: 'verification';
}
interface VerificationChallengeRequest {
    method: 'verificationChallenge';
    ciphertext: string;
}
interface AcknowledgementRequest {
    method: 'acknowledgement';
}
type Request = PublicKeyExchangeRequest | CommitmentRequest | NonceRevealRequest | VerificationRequest | VerificationChallengeRequest | AcknowledgementRequest;

interface InitiatorOptions {
    host: string;
    id: Identity;
    l: number;
    getConnectionString: () => Promise<string>;
}
declare abstract class InitiatorTransport<Req, Res> extends BaseTransport<Req, Res> {
    protected opts: InitiatorOptions;
    connString: ConnectionString | undefined;
    constructor(opts?: Partial<InitiatorOptions>);
    abstract sendRequest<T extends Request>(request: Request): Promise<T>;
    prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    publicKeyExchange(protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData>;
    authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    finish(protocol: WalletProtocol): void;
}

interface HttpRequest {
    url: string;
    init?: RequestInit;
}
interface HttpResponse {
    status: number;
    body: string;
}
declare class HttpInitiatorTransport extends InitiatorTransport<HttpRequest, HttpResponse> {
    baseSend(port: number, httpReq: RequestInit): Promise<HttpResponse>;
    sendRequest<T extends Request>(request: Request): Promise<T>;
    send(masterKey: MasterKey, code: Uint8Array, req: HttpRequest): Promise<HttpResponse>;
}

declare abstract class Response<T extends Request = Request> {
    abstract send(request: T): Promise<void>;
}

interface ResponderOptions {
    port: number;
    timeout: number;
    id: Identity;
    l: number;
    codeGenerator: CodeGenerator;
}
interface SubjectData<T extends Request = Request, S extends Request = Request> {
    req: T;
    res: Response<S>;
}
declare abstract class ResponderTransport<Req, Res> extends BaseTransport<Req, Res> {
    protected opts: ResponderOptions;
    protected rpcSubject: Subject<SubjectData>;
    protected lastPairing: NodeJS.Timeout | undefined;
    connString: ConnectionString | undefined;
    constructor(opts?: Partial<ResponderOptions>);
    pairing(protocol: WalletProtocol, port: number, timeout: number): Promise<void>;
    stopPairing(): void;
    get isPairing(): boolean;
    get port(): number;
    get timeout(): number;
    prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    waitRequest<M extends Request['method'], T extends (Request & {
        method: M;
    })>(method: M): Promise<SubjectData<T>>;
    publicKeyExchange(protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData>;
    authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    finish(protocol: WalletProtocol): void;
}

interface HttpResponderOptions extends ResponderOptions {
    rpcUrl: string;
}
declare class HttpResponderTransport extends ResponderTransport<http.IncomingMessage, never> {
    readonly rpcUrl: string;
    protected listeners: http.RequestListener[];
    constructor(opts?: Partial<HttpResponderOptions>);
    protected readRequestBody(req: http.IncomingMessage): Promise<string>;
    protected dispatchProtocolMessage(req: http.IncomingMessage, res: http.ServerResponse): Promise<void>;
    protected dispatchEncryptedMessage(req: http.IncomingMessage, res: http.ServerResponse, authentication: string): Promise<void>;
    dispatchRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void>;
    private callListeners;
    use(listener: http.RequestListener): void;
}

export { AuthData, BaseTransport, CodeGenerator, ConnectionString, HttpInitiatorTransport, HttpRequest, HttpResponderOptions, HttpResponderTransport, HttpResponse, Identity, InvalidPinError, MasterKey, PKEData, ProtocolAuthData, ProtocolPKEData, Queue, Session, Subject, Transport, TransportRequest, TransportResponse, WalletProtocol, WalletProtocolError, _default as constants, defaultCodeGenerator };
