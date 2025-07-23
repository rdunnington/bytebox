const std = @import("std");
const assert = std.debug.assert;

const def = @import("definition.zig");
const i8x16 = def.i8x16;
const u8x16 = def.u8x16;
const i16x8 = def.i16x8;
const u16x8 = def.u16x8;
const i32x4 = def.i32x4;
const u32x4 = def.u32x4;
const i64x2 = def.i64x2;
const u64x2 = def.u64x2;
const f32x4 = def.f32x4;
const f64x2 = def.f64x2;
const v128 = def.v128;
const Instruction = def.Instruction;
const Val = def.Val;
const ValType = def.ValType;

const inst = @import("instance.zig");
const ModuleInstance = inst.ModuleInstance;
const TrapError = inst.TrapError;

pub const FunctionInstance = struct {
    type_def_index: usize,
    def_index: usize,
    code: [*]const Instruction,
    instructions_begin: usize,
    num_locals: u32,
    num_params: u16,
    num_returns: u16,

    max_values: u32,
    max_labels: u32,

    module: *ModuleInstance,
};

pub const Label = struct {
    num_returns: u32,
    continuation: u32,
    start_offset_values: u32,
};

pub const CallFrame = struct {
    func: *const FunctionInstance,
    module_instance: *ModuleInstance,
    num_returns: u16,
    start_offset_values: u32,
    start_offset_labels: u16,
};

pub const FuncCallData = struct {
    code: [*]const Instruction,
    continuation: u32,
};

const Stack = @This();

values: []Val,
labels: []Label,
frames: []CallFrame,
num_values: u32,
num_labels: u16,
num_frames: u16,
mem: []u8,
allocator: std.mem.Allocator,

const AllocOpts = struct {
    max_values: u32,
    max_labels: u16,
    max_frames: u16,
};

pub fn init(allocator: std.mem.Allocator) Stack {
    const stack = Stack{
        .values = &[_]Val{},
        .labels = &[_]Label{},
        .frames = &[_]CallFrame{},
        .num_values = 0,
        .num_labels = 0,
        .num_frames = 0,
        .mem = &[_]u8{},
        .allocator = allocator,
    };

    return stack;
}

pub fn deinit(stack: *Stack) void {
    if (stack.mem.len > 0) {
        stack.allocator.free(stack.mem);
    }
}

pub fn allocMemory(stack: *Stack, opts: AllocOpts) !void {
    const alignment = @max(@alignOf(Val), @alignOf(Label), @alignOf(CallFrame));
    const values_alloc_size = std.mem.alignForward(usize, @as(usize, @intCast(opts.max_values)) * @sizeOf(Val), alignment);
    const labels_alloc_size = std.mem.alignForward(usize, @as(usize, @intCast(opts.max_labels)) * @sizeOf(Label), alignment);
    const frames_alloc_size = std.mem.alignForward(usize, @as(usize, @intCast(opts.max_frames)) * @sizeOf(CallFrame), alignment);
    const total_alloc_size: usize = values_alloc_size + labels_alloc_size + frames_alloc_size;

    const begin_labels = values_alloc_size;
    const begin_frames = values_alloc_size + labels_alloc_size;

    stack.mem = try stack.allocator.alloc(u8, total_alloc_size);
    stack.values.ptr = @as([*]Val, @alignCast(@ptrCast(stack.mem.ptr)));
    stack.values.len = opts.max_values;
    stack.labels.ptr = @as([*]Label, @alignCast(@ptrCast(stack.mem[begin_labels..].ptr)));
    stack.labels.len = opts.max_labels;
    stack.frames.ptr = @as([*]CallFrame, @alignCast(@ptrCast(stack.mem[begin_frames..].ptr)));
    stack.frames.len = opts.max_frames;
}

pub fn pushValue(stack: *Stack, value: Val) void {
    stack.values[stack.num_values] = value;
    stack.num_values += 1;
}

pub fn pushI32(stack: *Stack, v: i32) void {
    stack.values[stack.num_values] = Val{ .I32 = v };
    stack.num_values += 1;
}

pub fn pushI64(stack: *Stack, v: i64) void {
    stack.values[stack.num_values] = Val{ .I64 = v };
    stack.num_values += 1;
}

pub fn pushF32(stack: *Stack, v: f32) void {
    stack.values[stack.num_values] = Val{ .F32 = v };
    stack.num_values += 1;
}

pub fn pushF64(stack: *Stack, v: f64) void {
    stack.values[stack.num_values] = Val{ .F64 = v };
    stack.num_values += 1;
}

pub fn pushV128(stack: *Stack, v: v128) void {
    stack.values[stack.num_values] = Val{ .V128 = v };
    stack.num_values += 1;
}

pub fn popValue(stack: *Stack) Val {
    stack.num_values -= 1;
    const value: Val = stack.values[stack.num_values];
    return value;
}

pub fn topValue(stack: *const Stack) Val {
    return stack.values[stack.num_values - 1];
}

pub fn popI32(stack: *Stack) i32 {
    stack.num_values -= 1;
    return stack.values[stack.num_values].I32;
}

pub fn popI64(stack: *Stack) i64 {
    stack.num_values -= 1;
    return stack.values[stack.num_values].I64;
}

pub fn popF32(stack: *Stack) f32 {
    stack.num_values -= 1;
    return stack.values[stack.num_values].F32;
}

pub fn popF64(stack: *Stack) f64 {
    stack.num_values -= 1;
    return stack.values[stack.num_values].F64;
}

pub fn popV128(stack: *Stack) v128 {
    stack.num_values -= 1;
    return stack.values[stack.num_values].V128;
}

pub fn popIndexType(stack: *Stack) i64 {
    const index_type: ValType = stack.topFrame().module_instance.store.getMemory(0).limits.indexType();
    return switch (index_type) {
        .I32 => stack.popI32(),
        .I64 => stack.popI64(),
        else => unreachable,
    };
}

pub fn pushLabel(stack: *Stack, num_returns: u32, continuation: u32) !void {
    assert(stack.num_labels < stack.labels.len);

    stack.labels[stack.num_labels] = Label{
        .num_returns = num_returns,
        .continuation = continuation,
        .start_offset_values = stack.num_values,
    };
    stack.num_labels += 1;
}

pub fn popLabel(stack: *Stack) void {
    stack.num_labels -= 1;
}

pub fn findLabel(stack: Stack, id: u32) *const Label {
    const index: usize = (stack.num_labels - 1) - id;
    return &stack.labels[index];
}

pub fn topLabel(stack: Stack) *const Label {
    return &stack.labels[stack.num_labels - 1];
}

pub fn frameLabel(stack: Stack) *const Label {
    const frame: *const CallFrame = stack.topFrame();
    const frame_label: *const Label = &stack.labels[frame.start_offset_labels];
    return frame_label;
}

pub fn popAllUntilLabelId(stack: *Stack, label_id: u64, pop_final_label: bool, num_returns: usize) void {
    const label_index: u16 = @as(u16, @intCast((stack.num_labels - label_id) - 1));
    const label: *const Label = &stack.labels[label_index];

    if (pop_final_label) {
        const source_begin: usize = stack.num_values - num_returns;
        const source_end: usize = stack.num_values;
        const dest_begin: usize = label.start_offset_values;
        const dest_end: usize = label.start_offset_values + num_returns;

        const returns_source: []const Val = stack.values[source_begin..source_end];
        const returns_dest: []Val = stack.values[dest_begin..dest_end];
        if (dest_begin <= source_begin) {
            std.mem.copyForwards(Val, returns_dest, returns_source);
        } else {
            std.mem.copyBackwards(Val, returns_dest, returns_source);
        }

        stack.num_values = @as(u32, @intCast(dest_end));
        stack.num_labels = label_index;
    } else {
        stack.num_values = label.start_offset_values;
        stack.num_labels = label_index + 1;
    }
}

pub fn pushFrame(stack: *Stack, func: *const FunctionInstance, module_instance: *ModuleInstance) TrapError!void {
    // check stack exhaustion
    if (stack.frames.len <= stack.num_frames + 1) {
        @branchHint(std.builtin.BranchHint.cold);
        return error.TrapStackExhausted;
    }
    if (stack.values.len <= stack.num_values + func.max_values) {
        @branchHint(std.builtin.BranchHint.cold);
        return error.TrapStackExhausted;
    }
    if (stack.labels.len <= stack.num_labels + func.max_labels) {
        @branchHint(std.builtin.BranchHint.cold);
        return error.TrapStackExhausted;
    }

    // the stack should already be populated with the params to the function, so all that's
    // left to do is initialize the locals to their default values
    const values_index_begin: u32 = stack.num_values - func.num_params;
    const values_index_end: u32 = stack.num_values + func.num_locals;

    assert(stack.num_frames < stack.frames.len);
    assert(values_index_end < stack.values.len);

    const func_locals = stack.values[stack.num_values..values_index_end];

    // All locals must be initialized to their default value
    // https://webassembly.github.io/spec/core/exec/instructions.html#exec-invoke
    @memset(std.mem.sliceAsBytes(func_locals), 0);

    stack.num_values = values_index_end;

    stack.frames[stack.num_frames] = CallFrame{
        .func = func,
        .module_instance = module_instance,
        .num_returns = func.num_returns,
        .start_offset_values = values_index_begin,
        .start_offset_labels = stack.num_labels,
    };
    stack.num_frames += 1;
}

pub fn popFrame(stack: *Stack) ?FuncCallData {
    const frame: *CallFrame = stack.topFrame();

    const continuation: u32 = stack.labels[frame.start_offset_labels].continuation;
    const num_returns: usize = frame.num_returns;
    const source_begin: usize = stack.num_values - num_returns;
    const source_end: usize = stack.num_values;
    const dest_begin: usize = frame.start_offset_values;
    const dest_end: usize = frame.start_offset_values + num_returns;
    assert(dest_begin <= source_begin);

    // Because a function's locals take up stack space, the return values are located
    // after the locals, so we need to copy them back down to the start of the function's
    // stack space, where the caller expects them to be.
    const returns_source: []const Val = stack.values[source_begin..source_end];
    const returns_dest: []Val = stack.values[dest_begin..dest_end];
    std.mem.copyForwards(Val, returns_dest, returns_source);

    stack.num_values = @as(u32, @intCast(dest_end));
    stack.num_labels = frame.start_offset_labels;
    stack.num_frames -= 1;

    if (stack.num_frames > 0) {
        return FuncCallData{
            .code = stack.topFrame().func.code,
            .continuation = continuation,
        };
    }

    return null;
}

pub fn topFrame(stack: *const Stack) *CallFrame {
    return &stack.frames[stack.num_frames - 1];
}

pub fn locals(stack: *const Stack) []Val {
    const frame = stack.topFrame();
    return stack.values[frame.start_offset_values..];
}

pub fn popAll(stack: *Stack) void {
    stack.num_values = 0;
    stack.num_labels = 0;
    stack.num_frames = 0;
}

pub fn debugDump(stack: Stack) void {
    std.debug.print("===== stack dump =====\n", .{});
    for (stack.values[0..stack.num_values]) |val| {
        std.debug.print("I32: {}, I64: {}, F32: {}, F64: {}\n", .{ val.I32, val.I64, val.F32, val.F64 });
    }
    std.debug.print("======================\n", .{});
}
