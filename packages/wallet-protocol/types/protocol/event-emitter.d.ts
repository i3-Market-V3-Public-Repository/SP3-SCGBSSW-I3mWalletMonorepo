export declare class EventEmitter {
    events: Record<string, Function[]>;
    constructor();
    on(event: string, cb: Function): this;
    emit(event: string, ...data: any): boolean;
}
//# sourceMappingURL=event-emitter.d.ts.map