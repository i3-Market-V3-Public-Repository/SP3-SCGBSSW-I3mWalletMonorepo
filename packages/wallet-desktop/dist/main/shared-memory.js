"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SharedMemoryManager = void 0;
const events_1 = require("events");
const lib_1 = require("@wallet/lib");
class SharedMemoryManager extends events_1.EventEmitter {
    _memory;
    constructor(values) {
        super();
        this._memory = (0, lib_1.createDefaultSharedMemory)(values);
    }
    on(event, listener) {
        return super.on(event, listener);
    }
    once(event, listener) {
        return super.once(event, listener);
    }
    emit(event, ...args) {
        return super.emit(event, ...args);
    }
    update(modifier, emitter) {
        let sharedMemory;
        const oldSharedMemory = this._memory;
        if (typeof modifier === 'function') {
            sharedMemory = modifier(this._memory);
        }
        else {
            sharedMemory = modifier;
        }
        if (sharedMemory === undefined) {
            throw new Error('Shared memory update cannot be undefined');
        }
        else if (sharedMemory === this._memory) {
            throw new Error('Shared memory update must create a new object');
        }
        this._memory = sharedMemory;
        this.emit('change', this._memory, oldSharedMemory, emitter);
    }
    get memory() {
        return this._memory;
    }
}
exports.SharedMemoryManager = SharedMemoryManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2hhcmVkLW1lbW9yeS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9tYWluL3NoYXJlZC1tZW1vcnkudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQ0EsbUNBQXFDO0FBRXJDLHFDQUFxRTtBQUVyRSxNQUFhLG1CQUFvQixTQUFRLHFCQUFZO0lBQzNDLE9BQU8sQ0FBYztJQUU3QixZQUFhLE1BQThCO1FBQ3pDLEtBQUssRUFBRSxDQUFBO1FBQ1AsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFBLCtCQUF5QixFQUFDLE1BQU0sQ0FBQyxDQUFBO0lBQ2xELENBQUM7SUFHRCxFQUFFLENBQUUsS0FBc0IsRUFBRSxRQUFrQztRQUM1RCxPQUFPLEtBQUssQ0FBQyxFQUFFLENBQUMsS0FBSyxFQUFFLFFBQVEsQ0FBQyxDQUFBO0lBQ2xDLENBQUM7SUFHRCxJQUFJLENBQUUsS0FBc0IsRUFBRSxRQUFrQztRQUM5RCxPQUFPLEtBQUssQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLFFBQVEsQ0FBQyxDQUFBO0lBQ3BDLENBQUM7SUFHRCxJQUFJLENBQUUsS0FBc0IsRUFBRSxHQUFHLElBQVc7UUFDMUMsT0FBTyxLQUFLLENBQUMsSUFBSSxDQUFDLEtBQUssRUFBRSxHQUFHLElBQUksQ0FBQyxDQUFBO0lBQ25DLENBQUM7SUFJRCxNQUFNLENBQUUsUUFBYSxFQUFFLE9BQXVCO1FBQzVDLElBQUksWUFBc0MsQ0FBQTtRQUMxQyxNQUFNLGVBQWUsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFBO1FBQ3BDLElBQUksT0FBTyxRQUFRLEtBQUssVUFBVSxFQUFFO1lBQ2xDLFlBQVksR0FBRyxRQUFRLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFBO1NBQ3RDO2FBQU07WUFDTCxZQUFZLEdBQUcsUUFBUSxDQUFBO1NBQ3hCO1FBRUQsSUFBSSxZQUFZLEtBQUssU0FBUyxFQUFFO1lBQzlCLE1BQU0sSUFBSSxLQUFLLENBQUMsMENBQTBDLENBQUMsQ0FBQTtTQUM1RDthQUFNLElBQUksWUFBWSxLQUFLLElBQUksQ0FBQyxPQUFPLEVBQUU7WUFDeEMsTUFBTSxJQUFJLEtBQUssQ0FBQywrQ0FBK0MsQ0FBQyxDQUFBO1NBQ2pFO1FBQ0QsSUFBSSxDQUFDLE9BQU8sR0FBRyxZQUFZLENBQUE7UUFFM0IsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUUsSUFBSSxDQUFDLE9BQU8sRUFBRSxlQUFlLEVBQUUsT0FBTyxDQUFDLENBQUE7SUFDN0QsQ0FBQztJQUVELElBQUksTUFBTTtRQUNSLE9BQU8sSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUNyQixDQUFDO0NBQ0Y7QUEvQ0Qsa0RBK0NDIn0=