"use strict";
function findArguments(argv) {
    for (const arg of argv) {
        if (arg.startsWith('--args=')) {
            return arg.substring(7);
        }
    }
}
function loadArguments(argv) {
    const argumentsString = findArguments(argv);
    if (argumentsString !== undefined) {
        const jsonString = Buffer.from(argumentsString, 'base64').toString('utf8');
        const global = window;
        global.windowArgs = JSON.parse(jsonString);
    }
}
loadArguments(process.argv);
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicHJlbG9hZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9tYWluL3VpL3dpbmRvdy1tYW5hZ2VyL3ByZWxvYWQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUNBLFNBQVMsYUFBYSxDQUFFLElBQWM7SUFDcEMsS0FBSyxNQUFNLEdBQUcsSUFBSSxJQUFJLEVBQUU7UUFDdEIsSUFBSSxHQUFHLENBQUMsVUFBVSxDQUFDLFNBQVMsQ0FBQyxFQUFFO1lBQzdCLE9BQU8sR0FBRyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtTQUN4QjtLQUNGO0FBQ0gsQ0FBQztBQUVELFNBQVMsYUFBYSxDQUFFLElBQWM7SUFDcEMsTUFBTSxlQUFlLEdBQUcsYUFBYSxDQUFDLElBQUksQ0FBQyxDQUFBO0lBQzNDLElBQUksZUFBZSxLQUFLLFNBQVMsRUFBRTtRQUNqQyxNQUFNLFVBQVUsR0FBRyxNQUFNLENBQUMsSUFBSSxDQUFDLGVBQWUsRUFBRSxRQUFRLENBQUMsQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUE7UUFDMUUsTUFBTSxNQUFNLEdBQVEsTUFBYSxDQUFBO1FBQ2pDLE1BQU0sQ0FBQyxVQUFVLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUMsQ0FBQTtLQUMzQztBQUNILENBQUM7QUFFRCxhQUFhLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFBIn0=