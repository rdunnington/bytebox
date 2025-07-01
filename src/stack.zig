const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const config = @import("config");

const common = @import("common.zig");
const StableArray = common.StableArray;

const opcodes = @import("opcode.zig");
const Opcode = opcodes.Opcode;
const WasmOpcode = opcodes.WasmOpcode;

const def = @import("definition.zig");
pub const i8x16 = def.i8x16;
pub const u8x16 = def.u8x16;
pub const i16x8 = def.i16x8;
pub const u16x8 = def.u16x8;
pub const i32x4 = def.i32x4;
pub const u32x4 = def.u32x4;
pub const i64x2 = def.i64x2;
pub const u64x2 = def.u64x2;
pub const f32x4 = def.f32x4;
pub const f64x2 = def.f64x2;
pub const v128 = def.v128;
const BlockImmediates = def.BlockImmediates;
const BranchTableImmediates = def.BranchTableImmediates;
const CallIndirectImmediates = def.CallIndirectImmediates;
const ConstantExpression = def.ConstantExpression;
const DataDefinition = def.DataDefinition;
const ElementDefinition = def.ElementDefinition;
const ElementMode = def.ElementMode;
const FunctionDefinition = def.FunctionDefinition;
const FunctionExport = def.FunctionExport;
const FunctionHandle = def.FunctionHandle;
const FunctionHandleType = def.FunctionHandleType;
const FunctionTypeDefinition = def.FunctionTypeDefinition;
const GlobalDefinition = def.GlobalDefinition;
const GlobalMut = def.GlobalMut;
const IfImmediates = def.IfImmediates;
const ImportNames = def.ImportNames;
const Instruction = def.Instruction;
const Limits = def.Limits;
const MemoryDefinition = def.MemoryDefinition;
const MemoryOffsetAndLaneImmediates = def.MemoryOffsetAndLaneImmediates;
const ModuleDefinition = def.ModuleDefinition;
const NameCustomSection = def.NameCustomSection;
const TableDefinition = def.TableDefinition;
const TablePairImmediates = def.TablePairImmediates;
const Val = def.Val;
const ValType = def.ValType;

const inst = @import("instance.zig");
const UnlinkableError = inst.UnlinkableError;
const UninstantiableError = inst.UninstantiableError;
const ExportError = inst.ExportError;
const TrapError = inst.TrapError;
const HostFunctionError = inst.HostFunctionError;
const DebugTrace = inst.DebugTrace;
const TableInstance = inst.TableInstance;
const MemoryInstance = inst.MemoryInstance;
const GlobalInstance = inst.GlobalInstance;
const ElementInstance = inst.ElementInstance;
const FunctionImport = inst.FunctionImport;
const TableImport = inst.TableImport;
const MemoryImport = inst.MemoryImport;
const GlobalImport = inst.GlobalImport;
const ModuleImportPackage = inst.ModuleImportPackage;
const ModuleInstance = inst.ModuleInstance;
const VM = inst.VM;
const Store = inst.Store;
const ModuleInstantiateOpts = inst.ModuleInstantiateOpts;
const InvokeOpts = inst.InvokeOpts;
const ResumeInvokeOpts = inst.ResumeInvokeOpts;
const DebugTrapInstructionMode = inst.DebugTrapInstructionMode;

const metering = @import("metering.zig");

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
};

pub const Label = struct {
    num_returns: u32,
    continuation: u32,
    start_offset_values: u32,
};

pub const CallFrame = struct {
    func: *const FunctionInstance,
    module_instance: *ModuleInstance,
    locals: []Val,
    num_returns: u16,
    start_offset_values: u32,
    start_offset_labels: u16,
};

pub const FuncCallData = struct {
    code: [*]const Instruction,
    continuation: u32,
};

pub const Stack = struct {
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

    pub fn pushLabel(stack: *Stack, num_returns: u32, continuation: u32) void {
        std.debug.assert(stack.num_labels < stack.labels.len);

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

        std.debug.assert(stack.num_frames < stack.frames.len);
        std.debug.assert(values_index_end < stack.values.len);

        const locals_and_params: []Val = stack.values[values_index_begin..values_index_end];
        const locals = stack.values[stack.num_values..values_index_end];

        stack.num_values = values_index_end;

        // All locals must be initialized to their default value
        // https://webassembly.github.io/spec/core/exec/instructions.html#exec-invoke
        @memset(std.mem.sliceAsBytes(locals), 0);

        stack.frames[stack.num_frames] = CallFrame{
            .func = func,
            .module_instance = module_instance,
            .locals = locals_and_params,
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

    pub fn topFrame(stack: Stack) *CallFrame {
        return &stack.frames[stack.num_frames - 1];
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

    pub fn select(stack: *Stack) void {
        const boolean: i32 = stack.popI32();
        const v2: Val = stack.popValue();
        const v1: Val = stack.popValue();

        if (boolean != 0) {
            stack.pushValue(v1);
        } else {
            stack.pushValue(v2);
        }
    }

    pub fn selectT(stack: *Stack) void {
        const boolean: i32 = stack.popI32();
        const v2: Val = stack.popValue();
        const v1: Val = stack.popValue();

        if (boolean != 0) {
            stack.pushValue(v1);
        } else {
            stack.pushValue(v2);
        }
    }
};

fn traceInstruction(instruction_name: []const u8, pc: u32, stack: *const Stack) void {
    if (config.enable_debug_trace and DebugTrace.shouldTraceInstructions()) {
        const frame: *const CallFrame = stack.topFrame();
        const name_section: *const NameCustomSection = &frame.module_instance.module_def.name_section;
        const module_name = name_section.getModuleName();
        const function_name = name_section.findFunctionName(frame.func.def_index);

        std.debug.print("\t0x{x} - {s}!{s}: {s}\n", .{ pc, module_name, function_name, instruction_name });
    }
}
pub fn preamble(comptime Vm: type, name: []const u8, pc: u32, code: [*]const Instruction, stack: *Stack) TrapError!void {
    if (metering.enabled) {
        const root_module_instance: *ModuleInstance = stack.frames[0].module_instance;
        const root_stackvm = Vm.fromVM(root_module_instance.vm);

        if (root_stackvm.meter_state.enabled) {
            const meter = metering.reduce(root_stackvm.meter_state.meter, code[pc]);
            root_stackvm.meter_state.meter = meter;
            if (meter == 0) {
                root_stackvm.meter_state.pc = pc;
                root_stackvm.meter_state.opcode = code[pc].opcode;
                return metering.MeteringTrapError.TrapMeterExceeded;
            }
        }
    }

    if (config.enable_debug_trap) {
        const root_module_instance: *ModuleInstance = stack.frames[0].module_instance;
        const root_stackvm = Vm.fromVM(root_module_instance.vm);

        if (root_stackvm.debug_state) |*debug_state| {
            if (debug_state.trap_counter > 0) {
                debug_state.trap_counter -= 1;
                if (debug_state.trap_counter == 0) {
                    debug_state.pc = pc;
                    return error.TrapDebug;
                }
            }
        }
    }

    traceInstruction(name, pc, stack);
}

pub const OpHelpers = struct {
    const NanPropagateOp = enum {
        Min,
        Max,
    };

    pub fn propagateNanWithOp(comptime op: NanPropagateOp, v1: anytype, v2: @TypeOf(v1)) @TypeOf(v1) {
        if (std.math.isNan(v1)) {
            return v1;
        } else if (std.math.isNan(v2)) {
            return v2;
        } else {
            return switch (op) {
                .Min => @min(v1, v2),
                .Max => @max(v1, v2),
            };
        }
    }

    pub fn truncateTo(comptime T: type, value: anytype) TrapError!T {
        switch (T) {
            i32 => {},
            u32 => {},
            i64 => {},
            u64 => {},
            else => @compileError("Only i32 and i64 are supported outputs."),
        }
        switch (@TypeOf(value)) {
            f32 => {},
            f64 => {},
            else => @compileError("Only f32 and f64 are supported inputs."),
        }

        const truncated = @trunc(value);

        if (std.math.isNan(truncated)) {
            return error.TrapInvalidIntegerConversion;
        } else if (truncated < std.math.minInt(T)) {
            return error.TrapIntegerOverflow;
        } else {
            if (@typeInfo(T).int.bits < @typeInfo(@TypeOf(truncated)).float.bits) {
                if (truncated > std.math.maxInt(T)) {
                    return error.TrapIntegerOverflow;
                }
            } else {
                if (truncated >= std.math.maxInt(T)) {
                    return error.TrapIntegerOverflow;
                }
            }
        }
        return @as(T, @intFromFloat(truncated));
    }

    pub fn saturatedTruncateTo(comptime T: type, value: anytype) T {
        switch (T) {
            i32 => {},
            u32 => {},
            i64 => {},
            u64 => {},
            else => @compileError("Only i32 and i64 are supported outputs."),
        }
        switch (@TypeOf(value)) {
            f32 => {},
            f64 => {},
            else => @compileError("Only f32 and f64 are supported inputs."),
        }

        const truncated = @trunc(value);

        if (std.math.isNan(truncated)) {
            return 0;
        } else if (truncated < std.math.minInt(T)) {
            return std.math.minInt(T);
        } else {
            if (@typeInfo(T).int.bits < @typeInfo(@TypeOf(truncated)).float.bits) {
                if (truncated > std.math.maxInt(T)) {
                    return std.math.maxInt(T);
                }
            } else {
                if (truncated >= std.math.maxInt(T)) {
                    return std.math.maxInt(T);
                }
            }
        }
        return @as(T, @intFromFloat(truncated));
    }

    pub fn loadFromMem(comptime T: type, stack: *Stack, offset_from_memarg: u64) TrapError!T {
        const offset_from_stack: i64 = stack.popIndexType();
        if (offset_from_stack < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const store: *Store = &stack.topFrame().module_instance.store;
        const memory: *const MemoryInstance = store.getMemory(0);
        const offset_64: u64 = offset_from_memarg + @as(u64, @intCast(offset_from_stack));
        std.debug.assert(offset_64 <= std.math.maxInt(usize));
        const offset: usize = @intCast(offset_64);

        const bit_count = @bitSizeOf(T);
        const read_type = switch (bit_count) {
            8 => u8,
            16 => u16,
            32 => u32,
            64 => u64,
            128 => u128,
            else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
        };

        const end_offset = offset + (bit_count / 8);

        const buffer = memory.buffer();
        if (buffer.len < end_offset) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const mem = buffer[offset..end_offset];
        const byte_count = bit_count / 8;
        const value = std.mem.readInt(read_type, mem[0..byte_count], .little);
        return @as(T, @bitCast(value));
    }

    pub fn loadArrayFromMem(comptime read_type: type, comptime out_type: type, comptime array_len: usize, store: *Store, offset_from_memarg: u64, offset_from_stack: i32) TrapError![array_len]out_type {
        if (offset_from_stack < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const memory: *const MemoryInstance = store.getMemory(0);
        const offset_64: u64 = offset_from_memarg + @as(u64, @intCast(offset_from_stack));
        std.debug.assert(offset_64 <= std.math.maxInt(usize));
        const offset: usize = @intCast(offset_64);

        const byte_count = @sizeOf(read_type);
        const end_offset = offset + (byte_count * array_len);

        const buffer = memory.buffer();
        if (buffer.len < end_offset) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        var ret: [array_len]out_type = undefined;
        const mem = buffer[offset..end_offset];
        var i: usize = 0;
        while (i < array_len) : (i += 1) {
            const value_start = i * byte_count;
            const value_end = value_start + byte_count;
            ret[i] = std.mem.readInt(read_type, mem[value_start..value_end][0..byte_count], .little);
        }
        return ret;
    }

    pub fn storeInMem(value: anytype, stack: *Stack, offset_from_memarg: u64) TrapError!void {
        const offset_from_stack: i64 = stack.popIndexType();
        if (offset_from_stack < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const store: *Store = &stack.topFrame().module_instance.store;
        const memory: *MemoryInstance = store.getMemory(0);
        const offset_64: u64 = offset_from_memarg + @as(u64, @intCast(offset_from_stack));
        std.debug.assert(offset_64 <= std.math.maxInt(usize));
        const offset: usize = @intCast(offset_64);

        const bit_count = @bitSizeOf(@TypeOf(value));
        const write_type = switch (bit_count) {
            8 => u8,
            16 => u16,
            32 => u32,
            64 => u64,
            128 => u128,
            else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
        };

        const end_offset = offset + (bit_count / 8);
        const buffer = memory.buffer();

        if (buffer.len < end_offset) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const write_value = @as(write_type, @bitCast(value));

        const mem = buffer[offset..end_offset];
        const byte_count = bit_count / 8;
        std.mem.writeInt(write_type, mem[0..byte_count], write_value, .little);
    }

    pub fn memSize(stack: *Stack) void {
        const memory_index: usize = 0;
        var memory_instance: *const MemoryInstance = stack.topFrame().module_instance.store.getMemory(memory_index);

        switch (memory_instance.limits.indexType()) {
            .I32 => stack.pushI32(@intCast(memory_instance.size())),
            .I64 => stack.pushI64(@intCast(memory_instance.size())),
            else => unreachable,
        }
    }
    pub fn memGrow(stack: *Stack) void {
        const memory_index: usize = 0;
        var memory_instance: *MemoryInstance = stack.topFrame().module_instance.store.getMemory(memory_index);

        const old_num_pages: i32 = @as(i32, @intCast(memory_instance.limits.min));
        const num_pages: i64 = switch (memory_instance.limits.indexType()) {
            .I32 => stack.popI32(),
            .I64 => stack.popI64(),
            else => unreachable,
        };

        if (num_pages >= 0 and memory_instance.grow(@as(usize, @intCast(num_pages)))) {
            switch (memory_instance.limits.indexType()) {
                .I32 => stack.pushI32(old_num_pages),
                .I64 => stack.pushI64(old_num_pages),
                else => unreachable,
            }
        } else {
            switch (memory_instance.limits.indexType()) {
                .I32 => stack.pushI32(-1),
                .I64 => stack.pushI64(-1),
                else => unreachable,
            }
        }
    }

    pub fn callLocal(comptime Vm: type, stack: *Stack, pc: u32, code: [*]const Instruction) anyerror!FuncCallData {
        const func_index: u32 = code[pc].immediate.Index;
        const module_instance: *ModuleInstance = stack.topFrame().module_instance;
        const stack_vm = Vm.fromVM(module_instance.vm);

        std.debug.assert(func_index < stack_vm.functions.items.len);

        const func: *const FunctionInstance = &stack_vm.functions.items[@as(usize, @intCast(func_index))];
        return call(pc, stack, module_instance, func);
    }

    fn call(pc: u32, stack: *Stack, module_instance: *ModuleInstance, func: *const FunctionInstance) TrapError!FuncCallData {
        const continuation: u32 = pc + 1;
        try stack.pushFrame(func, module_instance);
        stack.pushLabel(func.num_returns, continuation);

        DebugTrace.traceFunction(module_instance, stack.num_frames, func.def_index);

        return FuncCallData{
            .code = func.code,
            .continuation = @intCast(func.instructions_begin),
        };
    }

    pub fn callImport(comptime Vm: type, stack: *Stack, pc: u32, code: [*]const Instruction) (TrapError || HostFunctionError)!FuncCallData {
        const func_index: u32 = code[pc].immediate.Index;
        const module_instance: *ModuleInstance = stack.topFrame().module_instance;
        const store: *const Store = &module_instance.store;

        std.debug.assert(func_index < store.imports.functions.items.len);

        const func = &store.imports.functions.items[func_index];

        switch (func.data) {
            .Host => |data| {
                const params_len: u32 = @as(u32, @intCast(data.func_def.getParams().len));
                const returns_len: u32 = @as(u32, @intCast(data.func_def.calcNumReturns()));

                std.debug.assert(stack.num_values + returns_len < stack.values.len);

                const module: *ModuleInstance = stack.topFrame().module_instance;
                const params = stack.values[stack.num_values - params_len .. stack.num_values];
                const returns_temp = stack.values[stack.num_values .. stack.num_values + returns_len];

                DebugTrace.traceHostFunction(module, stack.num_frames + 1, func.name);

                try data.callback(data.userdata, module, params.ptr, returns_temp.ptr);

                stack.num_values = (stack.num_values - params_len) + returns_len;
                const returns_dest = stack.values[stack.num_values - returns_len .. stack.num_values];

                if (params_len > 0) {
                    assert(@intFromPtr(returns_dest.ptr) < @intFromPtr(returns_temp.ptr));
                    std.mem.copyForwards(Val, returns_dest, returns_temp);
                } else {
                    // no copy needed in this case since the return values will go into the same location
                    assert(returns_dest.ptr == returns_temp.ptr);
                }

                return FuncCallData{
                    .code = stack.topFrame().module_instance.module_def.code.instructions.items.ptr,
                    .continuation = pc + 1,
                };
            },
            .Wasm => |data| {
                var stack_vm = Vm.fromVM(data.module_instance.vm);
                const func_instance: *const FunctionInstance = &stack_vm.functions.items[data.index];
                return try call(pc, stack, data.module_instance, func_instance);
            },
        }
    }

    pub fn callIndirect(comptime Vm: type, stack: *Stack, pc: u32, code: [*]const Instruction) anyerror!FuncCallData {
        const current_module: *ModuleInstance = stack.topFrame().module_instance;
        const immediates: *const CallIndirectImmediates = &code[pc].immediate.CallIndirect;
        const table_index: u32 = immediates.table_index;

        const table: *const TableInstance = current_module.store.getTable(table_index);

        const ref_index = stack.popI32();
        if (table.refs.items.len <= ref_index or ref_index < 0) {
            return error.TrapUndefinedElement;
        }

        const ref: Val = table.refs.items[@as(usize, @intCast(ref_index))];
        if (ref.isNull()) {
            return error.TrapUninitializedElement;
        }

        const func_index = ref.FuncRef.index;

        std.debug.assert(ref.FuncRef.module_instance != null); // Should have been set in module instantiation

        var call_module: *ModuleInstance = ref.FuncRef.module_instance.?;
        var call_store = &call_module.store;
        var call_stackvm = Vm.fromVM(call_module.vm);

        if (func_index >= call_store.imports.functions.items.len) {
            const func: *const FunctionInstance = &call_stackvm.functions.items[func_index - call_store.imports.functions.items.len];
            if (func.type_def_index != immediates.type_index) {
                const func_type_def: *const FunctionTypeDefinition = &call_module.module_def.types.items[func.type_def_index];
                const immediate_type_def: *const FunctionTypeDefinition = &call_module.module_def.types.items[immediates.type_index];

                var type_comparer = FunctionTypeDefinition.SortContext{};
                if (type_comparer.eql(func_type_def, immediate_type_def) == false) {
                    return error.TrapIndirectCallTypeMismatch;
                }
            }
            return call(pc, stack, call_module, func);
        } else {
            var func_import: *const FunctionImport = &call_store.imports.functions.items[func_index];
            const func_type_def: *const FunctionTypeDefinition = &call_module.module_def.types.items[immediates.type_index];
            if (func_import.isTypeSignatureEql(func_type_def) == false) {
                return error.TrapIndirectCallTypeMismatch;
            }
            return callImport(Vm, stack, pc, code);
        }
    }

    pub fn ifCond(stack: *Stack, pc: u32, code: [*]const Instruction) !u32 {
        const condition = stack.popI32();
        const immediate = code[pc].immediate.If;
        stack.pushLabel(immediate.num_returns, immediate.end_continuation);
        if (condition != 0) {
            return pc + 1;
        } else {
            return immediate.else_continuation + 1;
        }
    }

    pub fn ifNoElse(stack: *Stack, pc: u32, code: [*]const Instruction) !u32 {
        const condition = stack.popI32();
        const immediate = code[pc].immediate.If;
        if (condition != 0) {
            stack.pushLabel(immediate.num_returns, immediate.end_continuation);
            return pc + 1;
        } else {
            return immediate.else_continuation + 1;
        }
    }

    pub fn end(stack: *Stack, pc: u32, code: [*]const Instruction) ?FuncCallData {

        // TODO - this instruction tries to determine at runtime what behavior to take, but we can
        // probably determine this in the decode phase and split into 3 different end instructions
        // to avoid branching. Probably could bake the return types length into the immediate to avoid
        // cache misses on the lookup we're currently doing.
        const top_label: *const Label = stack.topLabel();
        const frame_label: *const Label = stack.frameLabel();

        if (top_label != frame_label) {
            // Since the only values on the stack should be the returns from the block, we just pop the
            // label, which leaves the value stack alone.
            stack.popLabel();

            return FuncCallData{
                .continuation = pc + 1,
                .code = code,
            };
        } else {
            return stack.popFrame();
        }
    }

    pub fn branch(stack: *Stack, label_id: u32) ?FuncCallData {
        const label: *const Label = stack.findLabel(@as(u32, @intCast(label_id)));
        const frame_label: *const Label = stack.frameLabel();
        // TODO generate BranchToFunctionEnd up if this can be statically determined at decode time (or just generate a Return?)
        if (label == frame_label) {
            return stack.popFrame();
        }

        // TODO split branches up into different types to avoid this lookup and if statement
        const module_def: *const ModuleDefinition = stack.topFrame().module_instance.module_def;
        const is_loop_continuation: bool = module_def.code.instructions.items[label.continuation].opcode == .Loop;

        if (is_loop_continuation == false or label_id != 0) {
            const pop_final_label = !is_loop_continuation;
            stack.popAllUntilLabelId(label_id, pop_final_label, label.num_returns);
        }

        return FuncCallData{
            .code = stack.topFrame().module_instance.module_def.code.instructions.items.ptr,
            .continuation = label.continuation + 1, // branching takes care of popping/pushing values so skip the End instruction
        };
    }

    pub fn branchIf(stack: *Stack, pc: u32, code: [*]const Instruction) ?FuncCallData {
        const v = stack.popI32();
        if (v != 0) {
            const label_id: u32 = code[pc].immediate.LabelId;
            return OpHelpers.branch(stack, label_id);
        } else {
            return FuncCallData{
                .code = code,
                .continuation = pc + 1,
            };
        }
    }

    pub fn branchTable(stack: *Stack, instruction: Instruction) ?FuncCallData {
        const module_instance: *const ModuleInstance = stack.topFrame().module_instance;
        const all_branch_table_immediates: []const BranchTableImmediates = stack.topFrame().module_instance.module_def.code.branch_table.items;
        const immediate_index = instruction.immediate.Index;

        const immediates: BranchTableImmediates = all_branch_table_immediates[immediate_index];
        const table: []const u32 = immediates.getLabelIds(module_instance.module_def.*);

        const label_index = stack.popI32();
        const label_id: u32 = if (label_index >= 0 and label_index < table.len) table[@as(usize, @intCast(label_index))] else immediates.fallback_id;
        const next: FuncCallData = OpHelpers.branch(stack, label_id) orelse return null;
        return next;
    }

    pub fn localGet(stack: *Stack, instruction: Instruction) void {
        const locals_index: u32 = instruction.immediate.Index;
        const top_frame: *const CallFrame = stack.topFrame();
        const v: Val = top_frame.locals[locals_index];
        stack.pushValue(v);
    }

    pub fn localSet(stack: *Stack, instruction: Instruction) !void {
        const locals_index: u32 = instruction.immediate.Index;
        var top_frame: *CallFrame = stack.topFrame();
        const v: Val = stack.popValue();
        top_frame.locals[locals_index] = v;
    }

    pub fn localTee(stack: *Stack, instruction: Instruction) !void {
        const locals_index: u32 = instruction.immediate.Index;
        var top_frame: *CallFrame = stack.topFrame();
        const v: Val = stack.topValue();
        top_frame.locals[locals_index] = v;
    }

    pub fn globalGet(stack: *Stack, instruction: Instruction) void {
        const global_index: u32 = instruction.immediate.Index;
        const global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        stack.pushValue(global.value);
    }
    pub fn globalSet(stack: *Stack, instruction: Instruction) !void {
        const global_index: u32 = instruction.immediate.Index;
        const global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        global.value = stack.popValue();
    }
    pub fn tableGet(stack: *Stack, instruction: Instruction) !void {
        const table_index: u32 = instruction.immediate.Index;
        const table: *const TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const index: i32 = stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        const ref = table.refs.items[@as(usize, @intCast(index))];
        stack.pushValue(ref);
    }

    pub fn tableSet(stack: *Stack, instruction: Instruction) !void {
        const table_index: u32 = instruction.immediate.Index;
        var table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const ref = stack.popValue();
        const index: i32 = stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        table.refs.items[@as(usize, @intCast(index))] = ref;
    }
    const VectorUnaryOp = enum(u8) {
        Ceil,
        Floor,
        Trunc,
        Nearest,
    };

    pub fn vectorUnOp(comptime T: type, op: VectorUnaryOp, stack: *Stack) void {
        const vec = @as(T, @bitCast(stack.popV128()));
        const type_info = @typeInfo(T).vector;
        const child_type = type_info.child;
        const result = switch (op) {
            .Ceil => @ceil(vec),
            .Floor => @floor(vec),
            .Trunc => @trunc(vec),
            .Nearest => blk: {
                const zeroes: T = @splat(0);
                const twos: T = @splat(2);

                const ceil = @ceil(vec);
                const floor = @floor(vec);
                const is_half = (ceil - vec) == (vec - floor);
                const evens = @select(child_type, @mod(ceil, twos) == zeroes, ceil, floor);
                const rounded = @round(vec);
                break :blk @select(child_type, is_half, evens, rounded);
            },
        };
        stack.pushV128(@as(v128, @bitCast(result)));
    }

    pub fn i32Const(stack: *Stack, instruction: Instruction) void {
        const v: i32 = instruction.immediate.ValueI32;
        stack.pushI32(v);
    }

    pub fn i64Const(stack: *Stack, instruction: Instruction) void {
        const v: i64 = instruction.immediate.ValueI64;
        stack.pushI64(v);
    }

    pub fn f32Const(stack: *Stack, instruction: Instruction) void {
        const v: f32 = instruction.immediate.ValueF32;
        stack.pushF32(v);
    }

    pub fn f64Const(stack: *Stack, instruction: Instruction) void {
        const v: f64 = instruction.immediate.ValueF64;
        stack.pushF64(v);
    }

    pub fn i32Eqz(stack: *Stack) void {
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 == 0) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32Eq(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32Ne(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32LtS(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32LtU(stack: *Stack) void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32GtS(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32GtU(stack: *Stack) void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32LeS(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32LeU(stack: *Stack) void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32GeS(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i32GeU(stack: *Stack) void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64Eqz(stack: *Stack) void {
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 == 0) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64Eq(stack: *Stack) void {
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64Ne(stack: *Stack) void {
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64LtS(stack: *Stack) void {
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64LtU(stack: *Stack) void {
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64GtS(stack: *Stack) void {
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64GtU(stack: *Stack) void {
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64LeS(stack: *Stack) void {
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64LeU(stack: *Stack) void {
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64GeS(stack: *Stack) void {
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn i64GeU(stack: *Stack) void {
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
    }

    pub fn f32Eq(stack: *Stack) void {
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f32Ne(stack: *Stack) void {
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f32Lt(stack: *Stack) void {
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f32Gt(stack: *Stack) void {
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f32Le(stack: *Stack) void {
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f32Ge(stack: *Stack) void {
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f64Eq(stack: *Stack) void {
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f64Ne(stack: *Stack) void {
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f64Lt(stack: *Stack) void {
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f64Gt(stack: *Stack) void {
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f64Le(stack: *Stack) void {
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn f64Ge(stack: *Stack) void {
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(value);
    }

    pub fn i32Clz(stack: *Stack) void {
        const v: i32 = stack.popI32();
        const num_zeroes = @clz(v);
        stack.pushI32(num_zeroes);
    }

    pub fn i32Ctz(stack: *Stack) void {
        const v: i32 = stack.popI32();
        const num_zeroes = @ctz(v);
        stack.pushI32(num_zeroes);
    }

    pub fn i32Popcnt(stack: *Stack) void {
        const v: i32 = stack.popI32();
        const num_bits_set = @popCount(v);
        stack.pushI32(num_bits_set);
    }

    pub fn i32Add(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result = v1 +% v2;
        stack.pushI32(result);
    }

    pub fn i32Sub(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result = v1 -% v2;
        stack.pushI32(result);
    }

    pub fn i32Mul(stack: *Stack) void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const value = v1 *% v2;
        stack.pushI32(value);
    }

    pub fn i32DivS(stack: *Stack) !void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const value = std.math.divTrunc(i32, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        stack.pushI32(value);
    }

    pub fn i32DivU(stack: *Stack) !void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value_unsigned = std.math.divFloor(u32, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        const value = @as(i32, @bitCast(value_unsigned));
        stack.pushI32(value);
    }

    pub fn i32RemS(stack: *Stack) !void {
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const denom: i32 = @intCast(@abs(v2));
        const value = std.math.rem(i32, v1, denom) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        stack.pushI32(value);
    }

    pub fn i32RemU(stack: *Stack) !void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value_unsigned = std.math.rem(u32, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        const value = @as(i32, @bitCast(value_unsigned));
        stack.pushI32(value);
    }

    pub fn i32And(stack: *Stack) void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(v1 & v2));
        stack.pushI32(value);
    }

    pub fn i32Or(stack: *Stack) void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(v1 | v2));
        stack.pushI32(value);
    }

    pub fn i32Xor(stack: *Stack) void {
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(v1 ^ v2));
        stack.pushI32(value);
    }

    pub fn i32Shl(stack: *Stack) !void {
        const shift_unsafe: i32 = stack.popI32();
        const int: i32 = stack.popI32();
        const shift: i32 = try std.math.mod(i32, shift_unsafe, 32);
        const value = std.math.shl(i32, int, shift);
        stack.pushI32(value);
    }

    pub fn i32ShrS(stack: *Stack) !void {
        const shift_unsafe: i32 = stack.popI32();
        const int: i32 = stack.popI32();
        const shift = try std.math.mod(i32, shift_unsafe, 32);
        const value = std.math.shr(i32, int, shift);
        stack.pushI32(value);
    }

    pub fn i32ShrU(stack: *Stack) !void {
        const shift_unsafe: u32 = @as(u32, @bitCast(stack.popI32()));
        const int: u32 = @as(u32, @bitCast(stack.popI32()));
        const shift = try std.math.mod(u32, shift_unsafe, 32);
        const value = @as(i32, @bitCast(std.math.shr(u32, int, shift)));
        stack.pushI32(value);
    }

    pub fn i32Rotl(stack: *Stack) void {
        const rot: u32 = @as(u32, @bitCast(stack.popI32()));
        const int: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(std.math.rotl(u32, int, rot)));
        stack.pushI32(value);
    }

    pub fn i32Rotr(stack: *Stack) void {
        const rot: u32 = @as(u32, @bitCast(stack.popI32()));
        const int: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(std.math.rotr(u32, int, rot)));
        stack.pushI32(value);
    }

    const VectorBinaryOp = enum(u8) {
        Add,
        Add_Sat,
        Sub,
        Sub_Sat,
        Mul,
        Div,
        Min,
        PMin,
        Max,
        PMax,
        And,
        AndNot,
        Or,
        Xor,
    };

    pub fn vectorOr(comptime len: usize, v1: @Vector(len, bool), v2: @Vector(len, bool)) @Vector(len, bool) {
        var arr: [len]bool = undefined;
        for (&arr, 0..) |*v, i| {
            v.* = v1[i] or v2[i];
        }
        return arr;
    }

    pub fn vectorBinOp(comptime T: type, comptime op: VectorBinaryOp, stack: *Stack) void {
        const type_info = @typeInfo(T).vector;
        const child_type = type_info.child;
        const v2 = @as(T, @bitCast(stack.popV128()));
        const v1 = @as(T, @bitCast(stack.popV128()));
        const result = switch (op) {
            .Add => blk: {
                break :blk switch (@typeInfo(child_type)) {
                    .int => v1 +% v2,
                    .float => v1 + v2,
                    else => unreachable,
                };
            },
            .Add_Sat => v1 +| v2,
            .Sub => blk: {
                break :blk switch (@typeInfo(child_type)) {
                    .int => v1 -% v2,
                    .float => v1 - v2,
                    else => unreachable,
                };
            },
            .Sub_Sat => v1 -| v2,
            .Mul => blk: {
                break :blk switch (@typeInfo(child_type)) {
                    .int => v1 *% v2,
                    .float => v1 * v2,
                    else => unreachable,
                };
            },
            .Div => v1 / v2,
            .Min => blk: {
                break :blk switch (@typeInfo(child_type)) {
                    .int => @min(v1, v2),
                    .float => blk2: {
                        const is_nan = v1 != v1;
                        const is_min = v1 < v2;
                        const pred = vectorOr(type_info.len, is_nan, is_min);
                        const r = @select(child_type, pred, v1, v2);
                        break :blk2 r;
                    },
                    else => unreachable,
                };
            },
            .PMin => @select(child_type, (v2 < v1), v2, v1),
            .Max => blk: {
                break :blk switch (@typeInfo(child_type)) {
                    .int => @max(v1, v2),
                    .float => blk2: {
                        const is_nan = v1 != v1;
                        const is_min = v1 > v2;
                        const pred = vectorOr(type_info.len, is_nan, is_min);
                        const r = @select(child_type, pred, v1, v2);
                        break :blk2 r;
                    },
                    else => unreachable,
                };
            },
            .PMax => @select(child_type, (v2 > v1), v2, v1),
            .And => v1 & v2,
            .AndNot => v1 & (~v2),
            .Or => v1 | v2,
            .Xor => v1 ^ v2,
        };
        stack.pushV128(@as(v128, @bitCast(result)));
    }

    pub fn vectorAbs(comptime T: type, stack: *Stack) void {
        const type_info = @typeInfo(T).vector;
        const child_type = type_info.child;
        const vec = @as(T, @bitCast(stack.popV128()));
        var arr: [type_info.len]child_type = undefined;
        for (&arr, 0..) |*v, i| {
            v.* = @as(child_type, @bitCast(@abs(vec[i])));
        }
        const abs: T = arr;
        stack.pushV128(@as(v128, @bitCast(abs)));
    }

    pub fn vectorAvgrU(comptime T: type, stack: *Stack) void {
        const type_info = @typeInfo(T).vector;
        const child_type = type_info.child;
        const type_big_width = std.meta.Int(.unsigned, @bitSizeOf(child_type) * 2);

        const v1 = @as(T, @bitCast(stack.popV128()));
        const v2 = @as(T, @bitCast(stack.popV128()));
        var arr: [type_info.len]child_type = undefined;
        for (&arr, 0..) |*v, i| {
            const vv1: type_big_width = v1[i];
            const vv2: type_big_width = v2[i];
            v.* = @as(child_type, @intCast(@divTrunc(vv1 + vv2 + 1, 2)));
        }
        const result: T = arr;
        stack.pushV128(@as(v128, @bitCast(result)));
    }

    const VectorBoolOp = enum(u8) {
        Eq,
        Ne,
        Lt,
        Gt,
        Le,
        Ge,
    };

    pub fn vectorBoolOp(comptime T: type, comptime op: VectorBoolOp, stack: *Stack) void {
        const v2 = @as(T, @bitCast(stack.popV128()));
        const v1 = @as(T, @bitCast(stack.popV128()));
        const bools = switch (op) {
            .Eq => v1 == v2,
            .Ne => v1 != v2,
            .Lt => v1 < v2,
            .Gt => v1 > v2,
            .Le => v1 <= v2,
            .Ge => v1 >= v2,
        };
        const vec_type_info = @typeInfo(T).vector;

        const no_bits: std.meta.Int(.unsigned, @bitSizeOf(vec_type_info.child)) = 0;
        const yes_bits = ~no_bits;

        const yes_vec: T = @splat(@bitCast(yes_bits));
        const no_vec: T = @splat(@bitCast(no_bits));
        const result: T = @select(vec_type_info.child, bools, yes_vec, no_vec);
        stack.pushV128(@as(v128, @bitCast(result)));
    }

    const VectorShiftDirection = enum {
        Left,
        Right,
    };

    pub fn vectorShift(comptime T: type, comptime direction: VectorShiftDirection, stack: *Stack) void {
        const shift_unsafe: i32 = stack.popI32();
        const vec = @as(T, @bitCast(stack.popV128()));
        const shift_safe = std.math.mod(i32, shift_unsafe, @bitSizeOf(@typeInfo(T).vector.child)) catch unreachable;
        const shift_fn = if (direction == .Left) std.math.shl else std.math.shr;
        const shifted = shift_fn(T, vec, shift_safe);
        stack.pushV128(@as(v128, @bitCast(shifted)));
    }

    pub fn vectorAllTrue(comptime T: type, vec: v128) i32 {
        const v = @as(T, @bitCast(vec));
        const zeroes: T = @splat(0);
        const bools = v != zeroes;
        const any_true: bool = @reduce(.And, bools);
        return if (any_true) 1 else 0;
    }

    pub fn vectorBitmask(comptime T: type, vec: v128) i32 {
        switch (@typeInfo(T)) {
            .vector => |vec_type_info| {
                switch (@typeInfo(vec_type_info.child)) {
                    .int => {},
                    else => @compileError("Vector child type must be an int"),
                }
            },
            else => @compileError("Expected T to be a vector type"),
        }

        const child_type: type = @typeInfo(T).vector.child;

        if (child_type == i8) {
            const high_bit: u8 = 1 << (@bitSizeOf(u8) - 1);
            const high_bits_mask: @Vector(16, u8) = @splat(high_bit);

            const shift_type = std.meta.Int(.unsigned, std.math.log2(@bitSizeOf(u16)));
            const shifts_left: @Vector(16, shift_type) = @splat(8);
            var shifts_right_array: [16]shift_type = undefined;
            for (&shifts_right_array, 0..) |*element, i| {
                element.* = @as(shift_type, @intCast(15 - i));
            }
            const shifts_right = @as(@Vector(16, shift_type), shifts_right_array);

            const v = @as(@Vector(16, u8), @bitCast(vec));
            const v_high_bits = high_bits_mask & v;
            const v_high_bits_u16: @Vector(16, u16) = v_high_bits;
            const v_high_bits_shifted_left = @shlExact(v_high_bits_u16, shifts_left);
            const v_high_bits_shifted_right = @shrExact(v_high_bits_shifted_left, shifts_right);
            const reduction: u32 = @reduce(.Or, v_high_bits_shifted_right);
            const bitmask = @as(i32, @bitCast(reduction));
            return bitmask;
        } else {
            const vec_len = @typeInfo(T).vector.len;
            const int_type: type = std.meta.Int(.unsigned, @bitSizeOf(child_type));

            const high_bit: int_type = 1 << (@bitSizeOf(int_type) - 1);
            const high_bits_mask: @Vector(vec_len, int_type) = @splat(high_bit);

            const shift_type = std.meta.Int(.unsigned, std.math.log2(@bitSizeOf(int_type)));
            var shifts_right_array: [vec_len]shift_type = undefined;
            for (&shifts_right_array, 0..) |*element, i| {
                element.* = @as(shift_type, @intCast((@bitSizeOf(int_type) - 1) - i));
            }
            const shifts_right = @as(@Vector(vec_len, shift_type), shifts_right_array);

            const v = @as(@Vector(vec_len, int_type), @bitCast(vec));
            const v_high_bits = high_bits_mask & v;
            const v_high_bits_shifted_right = @shrExact(v_high_bits, shifts_right);
            const reduction: u32 = @as(u32, @intCast(@reduce(.Or, v_high_bits_shifted_right))); // cast should be fine thanks to the rshift
            const bitmask = @as(i32, @bitCast(reduction));
            return bitmask;
        }
    }

    pub fn vectorLoadLane(comptime T: type, instruction: Instruction, stack: *Stack) !void {
        const vec_type_info = @typeInfo(T).vector;

        var vec = @as(T, @bitCast(stack.popV128()));
        const immediate = instruction.immediate.MemoryOffsetAndLane;
        const scalar = try loadFromMem(vec_type_info.child, stack, immediate.offset);
        vec[immediate.laneidx] = scalar;
        stack.pushV128(@as(v128, @bitCast(vec)));
    }

    pub fn vectorLoadExtend(comptime mem_type: type, comptime extend_type: type, comptime len: usize, mem_offset: u64, stack: *Stack) !void {
        const offset_from_stack: i32 = stack.popI32();
        const array: [len]extend_type = try OpHelpers.loadArrayFromMem(mem_type, extend_type, len, &stack.topFrame().module_instance.store, mem_offset, offset_from_stack);
        const vec: @Vector(len, extend_type) = array;
        stack.pushV128(@as(v128, @bitCast(vec)));
    }

    pub fn vectorLoadLaneZero(comptime T: type, instruction: Instruction, stack: *Stack) !void {
        const vec_type_info = @typeInfo(T).vector;

        const mem_offset = instruction.immediate.MemoryOffset;
        const scalar = try loadFromMem(vec_type_info.child, stack, mem_offset);
        var vec: T = @splat(0);
        vec[0] = scalar;
        stack.pushV128(@as(v128, @bitCast(vec)));
    }

    pub fn vectorStoreLane(comptime T: type, instruction: Instruction, stack: *Stack) !void {
        const vec = @as(T, @bitCast(stack.popV128()));
        const immediate = instruction.immediate.MemoryOffsetAndLane;
        const scalar = vec[immediate.laneidx];
        try storeInMem(scalar, stack, immediate.offset);
        stack.pushV128(@as(v128, @bitCast(vec)));
    }

    pub fn vectorExtractLane(comptime T: type, lane: u32, stack: *Stack) void {
        const vec = @as(T, @bitCast(stack.popV128()));
        const lane_value = vec[lane];

        const child_type = @typeInfo(T).vector.child;
        switch (child_type) {
            i8, u8, i16, u16, i32 => stack.pushI32(lane_value),
            i64 => stack.pushI64(lane_value),
            f32 => stack.pushF32(lane_value),
            f64 => stack.pushF64(lane_value),
            else => unreachable,
        }
    }

    pub fn vectorReplaceLane(comptime T: type, lane: u32, stack: *Stack) void {
        const child_type = @typeInfo(T).vector.child;
        const lane_value = switch (child_type) {
            i8, i16, i32 => @as(child_type, @truncate(stack.popI32())),
            i64 => stack.popI64(),
            f32 => stack.popF32(),
            f64 => stack.popF64(),
            else => unreachable,
        };
        var vec = @as(T, @bitCast(stack.popV128()));
        vec[lane] = lane_value;
        stack.pushV128(@as(v128, @bitCast(vec)));
    }

    const VectorSide = enum {
        Low,
        High,
    };

    const VectorConvert = enum {
        SafeCast,
        Saturate,
    };

    pub fn vectorAddPairwise(comptime in_type: type, comptime out_type: type, stack: *Stack) void {
        const out_info = @typeInfo(out_type).vector;

        const vec = @as(in_type, @bitCast(stack.popV128()));
        var arr: [out_info.len]out_info.child = undefined;
        for (&arr, 0..) |*v, i| {
            const v1: out_info.child = vec[i * 2];
            const v2: out_info.child = vec[(i * 2) + 1];
            v.* = v1 + v2;
        }
        const sum: out_type = arr;
        stack.pushV128(@as(v128, @bitCast(sum)));
    }

    pub fn vectorMulPairwise(comptime in_type: type, comptime out_type: type, side: OpHelpers.VectorSide, stack: *Stack) void {
        const info_out = @typeInfo(out_type).vector;

        const vec2 = @as(in_type, @bitCast(stack.popV128()));
        const vec1 = @as(in_type, @bitCast(stack.popV128()));

        var arr: [info_out.len]info_out.child = undefined;
        for (&arr, 0..) |*v, i| {
            const index = if (side == .Low) i else i + info_out.len;
            const v1: info_out.child = vec1[index];
            const v2: info_out.child = vec2[index];
            v.* = v1 * v2;
        }
        const product = arr;
        stack.pushV128(@as(v128, @bitCast(product)));
    }

    pub fn vectorExtend(comptime in_type: type, comptime out_type: type, comptime side: VectorSide, stack: *Stack) void {
        const in_info = @typeInfo(in_type).vector;
        const out_info = @typeInfo(out_type).vector;
        const side_offset = if (side == .Low) 0 else in_info.len / 2;

        const vec = @as(in_type, @bitCast(stack.popV128()));
        var arr: [out_info.len]out_info.child = undefined;
        for (&arr, 0..) |*v, i| {
            v.* = vec[i + side_offset];
        }
        const extended: out_type = arr;
        stack.pushV128(@as(v128, @bitCast(extended)));
    }

    pub fn saturate(comptime T: type, v: anytype) @TypeOf(v) {
        switch (@typeInfo(T)) {
            .int => {},
            else => unreachable,
        }
        const min = std.math.minInt(T);
        const max = std.math.maxInt(T);
        const clamped = std.math.clamp(v, min, max);
        return clamped;
    }

    pub fn vectorConvert(comptime in_type: type, comptime out_type: type, comptime side: VectorSide, convert: VectorConvert, stack: *Stack) void {
        const in_info = @typeInfo(in_type).vector;
        const out_info = @typeInfo(out_type).vector;
        const side_offset = if (side == .Low) 0 else in_info.len / 2;

        const vec_in = @as(in_type, @bitCast(stack.popV128()));
        var arr: [out_info.len]out_info.child = undefined;
        for (arr, 0..) |_, i| {
            const v: in_info.child = if (i < in_info.len) vec_in[i + side_offset] else 0;
            switch (@typeInfo(out_info.child)) {
                .int => arr[i] = blk: {
                    if (convert == .SafeCast) {
                        break :blk @as(out_info.child, @intFromFloat(v));
                    } else {
                        break :blk saturatedTruncateTo(out_info.child, v);
                    }
                },
                .float => arr[i] = @as(out_info.child, @floatFromInt(v)),
                else => unreachable,
            }
        }
        const vec_out: out_type = arr;
        stack.pushV128(@as(v128, @bitCast(vec_out)));
    }

    pub fn vectorNarrowingSaturate(comptime in_type: type, comptime out_type: type, vec: in_type) out_type {
        const in_info = @typeInfo(in_type).vector;
        const out_info = @typeInfo(out_type).vector;
        const T: type = out_info.child;

        std.debug.assert(out_info.len == in_info.len);

        var arr: [out_info.len]T = undefined;
        for (&arr, 0..) |*v, i| {
            v.* = @as(T, @intCast(std.math.clamp(vec[i], std.math.minInt(T), std.math.maxInt(T))));
        }
        return arr;
    }

    pub fn vectorNarrow(comptime in_type: type, comptime out_type: type, stack: *Stack) void {
        const out_info = @typeInfo(out_type).vector;

        const out_type_half = @Vector(out_info.len / 2, out_info.child);

        const v2 = @as(in_type, @bitCast(stack.popV128()));
        const v1 = @as(in_type, @bitCast(stack.popV128()));
        const v1_narrow: out_type_half = vectorNarrowingSaturate(in_type, out_type_half, v1);
        const v2_narrow: out_type_half = vectorNarrowingSaturate(in_type, out_type_half, v2);
        const mask = switch (out_info.len) {
            16 => @Vector(16, i32){ 0, 1, 2, 3, 4, 5, 6, 7, -1, -2, -3, -4, -5, -6, -7, -8 },
            8 => @Vector(8, i32){ 0, 1, 2, 3, -1, -2, -3, -4 },
            4 => @Vector(8, i32){ 0, 1, -1, -2 },
            else => unreachable,
        };

        const mix = @shuffle(out_info.child, v1_narrow, v2_narrow, mask);
        stack.pushV128(@as(v128, @bitCast(mix)));
    }
};
