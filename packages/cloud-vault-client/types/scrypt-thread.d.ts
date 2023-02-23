/// <reference types="node" />
import { KeyObject } from 'crypto';
import type { KeyDerivationOptions } from './key-manager';
export interface scryptThreadWorkerData {
    _name: 'scrypt-thread';
    passwordOrKey: string | KeyObject;
    opts: KeyDerivationOptions;
}
//# sourceMappingURL=scrypt-thread.d.ts.map