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
const InstructionStream = def.InstructionStream;
const InstructionStreamReader = def.InstructionStreamReader;

const inst = @import("instance.zig");
const UnlinkableError = inst.UnlinkableError;
const UninstantiableError = inst.UninstantiableError;
const ExportError = inst.ExportError;
const TrapError = inst.TrapError;
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

const DebugTraceStackVM = struct {
    fn traceInstruction(instruction_name: []const u8, pc: usize, stack: *const Stack) void {
        if (DebugTrace.shouldTraceInstructions()) {
            const frame: *const CallFrame = stack.topFrame();
            const name_section: *const NameCustomSection = &frame.module_instance.module_def.name_section;
            const module_name = name_section.getModuleName();
            const function_name = name_section.findFunctionName(frame.func.def_index);

            std.debug.print("\t0x{x} - {s}!{s}: {s}\n", .{ pc, module_name, function_name, instruction_name });
        }
    }
};

const FunctionInstance = struct {
    type_def_index: usize,
    def_index: usize,
    instructions_begin: u32,
    local_types: std.ArrayList(ValType),

    fn deinit(func: *FunctionInstance) void {
        func.local_types.deinit();
    }
};

const Label = struct {
    continuation: u32,
    num_returns: u32,
    start_offset_values: u32,
    is_loop_continuation: bool,
};

const CallFrame = struct {
    func: *const FunctionInstance,
    module_instance: *ModuleInstance,
    locals: []Val,
    num_returns: u32,
    start_offset_values: u32,
    start_offset_labels: u16,
};

const Stack = struct {
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

    fn init(allocator: std.mem.Allocator) Stack {
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

    fn deinit(stack: *Stack) void {
        if (stack.mem.len > 0) {
            stack.allocator.free(stack.mem);
        }
    }

    fn allocMemory(stack: *Stack, opts: AllocOpts) !void {
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

    fn checkExhausted(stack: *Stack, extra_values: u32) TrapError!void {
        if (stack.num_values + extra_values >= stack.values.len) {
            return error.TrapStackExhausted;
        }
    }

    fn pushValue(stack: *Stack, value: Val) void {
        stack.values[stack.num_values] = value;
        stack.num_values += 1;
    }

    fn pushI32(stack: *Stack, v: i32) void {
        stack.values[stack.num_values] = Val{ .I32 = v };
        stack.num_values += 1;
    }

    fn pushI64(stack: *Stack, v: i64) void {
        stack.values[stack.num_values] = Val{ .I64 = v };
        stack.num_values += 1;
    }

    fn pushF32(stack: *Stack, v: f32) void {
        stack.values[stack.num_values] = Val{ .F32 = v };
        stack.num_values += 1;
    }

    fn pushF64(stack: *Stack, v: f64) void {
        stack.values[stack.num_values] = Val{ .F64 = v };
        stack.num_values += 1;
    }

    fn pushV128(stack: *Stack, v: v128) void {
        stack.values[stack.num_values] = Val{ .V128 = v };
        stack.num_values += 1;
    }

    fn popValue(stack: *Stack) Val {
        stack.num_values -= 1;
        const value: Val = stack.values[stack.num_values];
        return value;
    }

    fn topValue(stack: *const Stack) Val {
        return stack.values[stack.num_values - 1];
    }

    fn popI32(stack: *Stack) i32 {
        stack.num_values -= 1;
        return stack.values[stack.num_values].I32;
    }

    fn popI64(stack: *Stack) i64 {
        stack.num_values -= 1;
        return stack.values[stack.num_values].I64;
    }

    fn popF32(stack: *Stack) f32 {
        stack.num_values -= 1;
        return stack.values[stack.num_values].F32;
    }

    fn popF64(stack: *Stack) f64 {
        stack.num_values -= 1;
        return stack.values[stack.num_values].F64;
    }

    fn popV128(stack: *Stack) v128 {
        stack.num_values -= 1;
        return stack.values[stack.num_values].V128;
    }

    fn popIndexType(stack: *Stack) i64 {
        const index_type: ValType = stack.topFrame().module_instance.store.getMemory(0).limits.indexType();
        return switch (index_type) {
            .I32 => stack.popI32(),
            .I64 => stack.popI64(),
            else => unreachable,
        };
    }

    fn pushLabel(stack: *Stack, opcode: Opcode, num_returns: u32, continuation: u32) TrapError!void {
        if (stack.num_labels < stack.labels.len) {
            stack.labels[stack.num_labels] = Label{
                .is_loop_continuation = (opcode == .Loop),
                .num_returns = num_returns,
                .continuation = continuation,
                .start_offset_values = stack.num_values,
            };
            stack.num_labels += 1;
        } else {
            return error.TrapStackExhausted;
        }
    }

    fn popLabel(stack: *Stack) void {
        stack.num_labels -= 1;
    }

    fn findLabel(stack: Stack, id: u32) *const Label {
        const index: usize = (stack.num_labels - 1) - id;
        return &stack.labels[index];
    }

    fn topLabel(stack: Stack) *const Label {
        return &stack.labels[stack.num_labels - 1];
    }

    fn frameLabel(stack: Stack) *const Label {
        const frame: *const CallFrame = stack.topFrame();
        const frame_label: *const Label = &stack.labels[frame.start_offset_labels];
        return frame_label;
    }

    fn popAllUntilLabelId(stack: *Stack, label_id: u64, pop_final_label: bool, num_returns: usize) void {
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

    fn pushFrame(stack: *Stack, func: *const FunctionInstance, module_instance: *ModuleInstance, param_types: []const ValType, all_local_types: []const ValType, num_returns: u32) TrapError!void {
        const non_param_types: []const ValType = all_local_types[param_types.len..];

        // the stack should already be populated with the params to the function, so all that's
        // left to do is initialize the locals to their default values
        const values_index_begin: u32 = stack.num_values - @as(u32, @intCast(param_types.len));
        const values_index_end: u32 = stack.num_values + @as(u32, @intCast(non_param_types.len));

        if (stack.num_frames < stack.frames.len and values_index_end < stack.values.len) {
            const locals_and_params: []Val = stack.values[values_index_begin..values_index_end];
            var locals = stack.values[stack.num_values..values_index_end];

            stack.num_values = values_index_end;

            for (non_param_types, 0..) |valtype, i| {
                locals[i] = Val.default(valtype);
            }

            stack.frames[stack.num_frames] = CallFrame{
                .func = func,
                .module_instance = module_instance,
                .locals = locals_and_params,
                .num_returns = num_returns,
                .start_offset_values = values_index_begin,
                .start_offset_labels = stack.num_labels,
            };
            stack.num_frames += 1;
        } else {
            return error.TrapStackExhausted;
        }
    }

    fn popFrame(stack: *Stack) ?*InstructionStreamReader {
        const frame: *CallFrame = stack.topFrame();
        const frame_label: Label = stack.labels[frame.start_offset_labels];

        const num_returns: usize = frame.num_returns;
        const source_begin: usize = stack.num_values - num_returns;
        const source_end: usize = stack.num_values;
        const dest_begin: usize = frame.start_offset_values;
        const dest_end: usize = frame.start_offset_values + num_returns;

        const returns_source: []const Val = stack.values[source_begin..source_end];
        const returns_dest: []Val = stack.values[dest_begin..dest_end];
        assert(dest_begin <= source_begin);
        std.mem.copyForwards(Val, returns_dest, returns_source);

        stack.num_values = @as(u32, @intCast(dest_end));
        stack.num_labels = frame.start_offset_labels;
        stack.num_frames -= 1;

        if (stack.num_frames > 0) {
            const stackvm: *StackVM = StackVM.fromVM(stack.topFrame().module_instance.vm);
            var code: *InstructionStreamReader = &stackvm.instructions_reader;
            code.jump(frame_label.continuation);
            return code;
        }

        return null;
    }

    fn topFrame(stack: Stack) *CallFrame {
        return &stack.frames[stack.num_frames - 1];
    }

    fn popAll(stack: *Stack) void {
        stack.num_values = 0;
        stack.num_labels = 0;
        stack.num_frames = 0;
    }

    fn debugDump(stack: Stack) void {
        std.debug.print("===== stack dump =====\n", .{});
        for (stack.values[0..stack.num_values]) |val| {
            std.debug.print("I32: {}, I64: {}, F32: {}, F64: {}\n", .{ val.I32, val.I64, val.F32, val.F64 });
        }
        std.debug.print("======================\n", .{});
    }
};

// TODO: should only be able to return a TrapError
const InstructionFunc = *const fn (code: *InstructionStreamReader, stack: *Stack) anyerror!void;

// Maps all instructions to an execution function, to map opcodes directly to function pointers
// which avoids a giant switch statement. Because the switch-style has a single conditional
// branch for every opcode, the branch predictor cannot reliably predict the next opcode. However,
// giving each instruction its own branch allows the branch predictor to cache heuristics for each
// instruction, instead of a single branch. This approach is combined with tail calls to ensure the
// stack doesn't overflow and help optimize the generated asm.
// In the past, this style of opcode dispatch has been called the poorly-named "threaded code" approach.
// See the "continuation-passing style" section of this article:
// http://www.complang.tuwien.ac.at/forth/threaded-code.html
const InstructionFuncs = struct {
    const opcodeToFuncTable = [_]InstructionFunc{
        &op_Invalid,
        &op_Unreachable,
        &op_DebugTrap,
        &op_Noop,
        &op_Block,
        &op_Loop,
        &op_If,
        &op_IfNoElse,
        &op_Else,
        &op_End,
        &op_Branch,
        &op_Branch_If,
        &op_Branch_Table,
        &op_Return,
        &op_Call,
        &op_Call_Indirect,
        &op_Drop,
        &op_Select,
        &op_Select_T,
        &op_Local_Get,
        &op_Local_Set,
        &op_Local_Tee,
        &op_Global_Get,
        &op_Global_Set,
        &op_Table_Get,
        &op_Table_Set,
        &op_I32_Load,
        &op_I64_Load,
        &op_F32_Load,
        &op_F64_Load,
        &op_I32_Load8_S,
        &op_I32_Load8_U,
        &op_I32_Load16_S,
        &op_I32_Load16_U,
        &op_I64_Load8_S,
        &op_I64_Load8_U,
        &op_I64_Load16_S,
        &op_I64_Load16_U,
        &op_I64_Load32_S,
        &op_I64_Load32_U,
        &op_I32_Store,
        &op_I64_Store,
        &op_F32_Store,
        &op_F64_Store,
        &op_I32_Store8,
        &op_I32_Store16,
        &op_I64_Store8,
        &op_I64_Store16,
        &op_I64_Store32,
        &op_Memory_Size,
        &op_Memory_Grow,
        &op_I32_Const,
        &op_I64_Const,
        &op_F32_Const,
        &op_F64_Const,
        &op_I32_Eqz,
        &op_I32_Eq,
        &op_I32_NE,
        &op_I32_LT_S,
        &op_I32_LT_U,
        &op_I32_GT_S,
        &op_I32_GT_U,
        &op_I32_LE_S,
        &op_I32_LE_U,
        &op_I32_GE_S,
        &op_I32_GE_U,
        &op_I64_Eqz,
        &op_I64_Eq,
        &op_I64_NE,
        &op_I64_LT_S,
        &op_I64_LT_U,
        &op_I64_GT_S,
        &op_I64_GT_U,
        &op_I64_LE_S,
        &op_I64_LE_U,
        &op_I64_GE_S,
        &op_I64_GE_U,
        &op_F32_EQ,
        &op_F32_NE,
        &op_F32_LT,
        &op_F32_GT,
        &op_F32_LE,
        &op_F32_GE,
        &op_F64_EQ,
        &op_F64_NE,
        &op_F64_LT,
        &op_F64_GT,
        &op_F64_LE,
        &op_F64_GE,
        &op_I32_Clz,
        &op_I32_Ctz,
        &op_I32_Popcnt,
        &op_I32_Add,
        &op_I32_Sub,
        &op_I32_Mul,
        &op_I32_Div_S,
        &op_I32_Div_U,
        &op_I32_Rem_S,
        &op_I32_Rem_U,
        &op_I32_And,
        &op_I32_Or,
        &op_I32_Xor,
        &op_I32_Shl,
        &op_I32_Shr_S,
        &op_I32_Shr_U,
        &op_I32_Rotl,
        &op_I32_Rotr,
        &op_I64_Clz,
        &op_I64_Ctz,
        &op_I64_Popcnt,
        &op_I64_Add,
        &op_I64_Sub,
        &op_I64_Mul,
        &op_I64_Div_S,
        &op_I64_Div_U,
        &op_I64_Rem_S,
        &op_I64_Rem_U,
        &op_I64_And,
        &op_I64_Or,
        &op_I64_Xor,
        &op_I64_Shl,
        &op_I64_Shr_S,
        &op_I64_Shr_U,
        &op_I64_Rotl,
        &op_I64_Rotr,
        &op_F32_Abs,
        &op_F32_Neg,
        &op_F32_Ceil,
        &op_F32_Floor,
        &op_F32_Trunc,
        &op_F32_Nearest,
        &op_F32_Sqrt,
        &op_F32_Add,
        &op_F32_Sub,
        &op_F32_Mul,
        &op_F32_Div,
        &op_F32_Min,
        &op_F32_Max,
        &op_F32_Copysign,
        &op_F64_Abs,
        &op_F64_Neg,
        &op_F64_Ceil,
        &op_F64_Floor,
        &op_F64_Trunc,
        &op_F64_Nearest,
        &op_F64_Sqrt,
        &op_F64_Add,
        &op_F64_Sub,
        &op_F64_Mul,
        &op_F64_Div,
        &op_F64_Min,
        &op_F64_Max,
        &op_F64_Copysign,
        &op_I32_Wrap_I64,
        &op_I32_Trunc_F32_S,
        &op_I32_Trunc_F32_U,
        &op_I32_Trunc_F64_S,
        &op_I32_Trunc_F64_U,
        &op_I64_Extend_I32_S,
        &op_I64_Extend_I32_U,
        &op_I64_Trunc_F32_S,
        &op_I64_Trunc_F32_U,
        &op_I64_Trunc_F64_S,
        &op_I64_Trunc_F64_U,
        &op_F32_Convert_I32_S,
        &op_F32_Convert_I32_U,
        &op_F32_Convert_I64_S,
        &op_F32_Convert_I64_U,
        &op_F32_Demote_F64,
        &op_F64_Convert_I32_S,
        &op_F64_Convert_I32_U,
        &op_F64_Convert_I64_S,
        &op_F64_Convert_I64_U,
        &op_F64_Promote_F32,
        &op_I32_Reinterpret_F32,
        &op_I64_Reinterpret_F64,
        &op_F32_Reinterpret_I32,
        &op_F64_Reinterpret_I64,
        &op_I32_Extend8_S,
        &op_I32_Extend16_S,
        &op_I64_Extend8_S,
        &op_I64_Extend16_S,
        &op_I64_Extend32_S,
        &op_Ref_Null,
        &op_Ref_Is_Null,
        &op_Ref_Func,
        &op_I32_Trunc_Sat_F32_S,
        &op_I32_Trunc_Sat_F32_U,
        &op_I32_Trunc_Sat_F64_S,
        &op_I32_Trunc_Sat_F64_U,
        &op_I64_Trunc_Sat_F32_S,
        &op_I64_Trunc_Sat_F32_U,
        &op_I64_Trunc_Sat_F64_S,
        &op_I64_Trunc_Sat_F64_U,
        &op_Memory_Init,
        &op_Data_Drop,
        &op_Memory_Copy,
        &op_Memory_Fill,
        &op_Table_Init,
        &op_Elem_Drop,
        &op_Table_Copy,
        &op_Table_Grow,
        &op_Table_Size,
        &op_Table_Fill,
        &op_V128_Load,
        &op_V128_Load8x8_S,
        &op_V128_Load8x8_U,
        &op_V128_Load16x4_S,
        &op_V128_Load16x4_U,
        &op_V128_Load32x2_S,
        &op_V128_Load32x2_U,
        &op_V128_Load8_Splat,
        &op_V128_Load16_Splat,
        &op_V128_Load32_Splat,
        &op_V128_Load64_Splat,
        &op_V128_Store,
        &op_V128_Const,
        &op_I8x16_Shuffle,
        &op_I8x16_Swizzle,
        &op_I8x16_Splat,
        &op_I16x8_Splat,
        &op_I32x4_Splat,
        &op_I64x2_Splat,
        &op_F32x4_Splat,
        &op_F64x2_Splat,
        &op_I8x16_Extract_Lane_S,
        &op_I8x16_Extract_Lane_U,
        &op_I8x16_Replace_Lane,
        &op_I16x8_Extract_Lane_S,
        &op_I16x8_Extract_Lane_U,
        &op_I16x8_Replace_Lane,
        &op_I32x4_Extract_Lane,
        &op_I32x4_Replace_Lane,
        &op_I64x2_Extract_Lane,
        &op_I64x2_Replace_Lane,
        &op_F32x4_Extract_Lane,
        &op_F32x4_Replace_Lane,
        &op_F64x2_Extract_Lane,
        &op_F64x2_Replace_Lane,
        &op_I8x16_EQ,
        &op_I8x16_NE,
        &op_I8x16_LT_S,
        &op_I8x16_LT_U,
        &op_I8x16_GT_S,
        &op_I8x16_GT_U,
        &op_I8x16_LE_S,
        &op_I8x16_LE_U,
        &op_I8x16_GE_S,
        &op_I8x16_GE_U,
        &op_I16x8_EQ,
        &op_I16x8_NE,
        &op_I16x8_LT_S,
        &op_I16x8_LT_U,
        &op_I16x8_GT_S,
        &op_I16x8_GT_U,
        &op_I16x8_LE_S,
        &op_I16x8_LE_U,
        &op_I16x8_GE_S,
        &op_I16x8_GE_U,
        &op_I32x4_EQ,
        &op_I32x4_NE,
        &op_I32x4_LT_S,
        &op_I32x4_LT_U,
        &op_I32x4_GT_S,
        &op_I32x4_GT_U,
        &op_I32x4_LE_S,
        &op_I32x4_LE_U,
        &op_I32x4_GE_S,
        &op_I32x4_GE_U,
        &op_F32x4_EQ,
        &op_F32x4_NE,
        &op_F32x4_LT,
        &op_F32x4_GT,
        &op_F32x4_LE,
        &op_F32x4_GE,
        &op_F64x2_EQ,
        &op_F64x2_NE,
        &op_F64x2_LT,
        &op_F64x2_GT,
        &op_F64x2_LE,
        &op_F64x2_GE,
        &op_V128_Not,
        &op_V128_And,
        &op_V128_AndNot,
        &op_V128_Or,
        &op_V128_Xor,
        &op_V128_Bitselect,
        &op_V128_AnyTrue,
        &op_V128_Load8_Lane,
        &op_V128_Load16_Lane,
        &op_V128_Load32_Lane,
        &op_V128_Load64_Lane,
        &op_V128_Store8_Lane,
        &op_V128_Store16_Lane,
        &op_V128_Store32_Lane,
        &op_V128_Store64_Lane,
        &op_V128_Load32_Zero,
        &op_V128_Load64_Zero,
        &op_F32x4_Demote_F64x2_Zero,
        &op_F64x2_Promote_Low_F32x4,
        &op_I8x16_Abs,
        &op_I8x16_Neg,
        &op_I8x16_Popcnt,
        &op_I8x16_AllTrue,
        &op_I8x16_Bitmask,
        &op_I8x16_Narrow_I16x8_S,
        &op_I8x16_Narrow_I16x8_U,
        &op_F32x4_Ceil,
        &op_F32x4_Floor,
        &op_F32x4_Trunc,
        &op_F32x4_Nearest,
        &op_I8x16_Shl,
        &op_I8x16_Shr_S,
        &op_I8x16_Shr_U,
        &op_I8x16_Add,
        &op_I8x16_Add_Sat_S,
        &op_I8x16_Add_Sat_U,
        &op_I8x16_Sub,
        &op_I8x16_Sub_Sat_S,
        &op_I8x16_Sub_Sat_U,
        &op_F64x2_Ceil,
        &op_F64x2_Floor,
        &op_I8x16_Min_S,
        &op_I8x16_Min_U,
        &op_I8x16_Max_S,
        &op_I8x16_Max_U,
        &op_F64x2_Trunc,
        &op_I8x16_Avgr_U,
        &op_I16x8_Extadd_Pairwise_I8x16_S,
        &op_I16x8_Extadd_Pairwise_I8x16_U,
        &op_I32x4_Extadd_Pairwise_I16x8_S,
        &op_I32x4_Extadd_Pairwise_I16x8_U,
        &op_I16x8_Abs,
        &op_I16x8_Neg,
        &op_I16x8_Q15mulr_Sat_S,
        &op_I16x8_AllTrue,
        &op_I16x8_Bitmask,
        &op_I16x8_Narrow_I32x4_S,
        &op_I16x8_Narrow_I32x4_U,
        &op_I16x8_Extend_Low_I8x16_S,
        &op_I16x8_Extend_High_I8x16_S,
        &op_I16x8_Extend_Low_I8x16_U,
        &op_I16x8_Extend_High_I8x16_U,
        &op_I16x8_Shl,
        &op_I16x8_Shr_S,
        &op_I16x8_Shr_U,
        &op_I16x8_Add,
        &op_I16x8_Add_Sat_S,
        &op_I16x8_Add_Sat_U,
        &op_I16x8_Sub,
        &op_I16x8_Sub_Sat_S,
        &op_I16x8_Sub_Sat_U,
        &op_F64x2_Nearest,
        &op_I16x8_Mul,
        &op_I16x8_Min_S,
        &op_I16x8_Min_U,
        &op_I16x8_Max_S,
        &op_I16x8_Max_U,
        &op_I16x8_Avgr_U,
        &op_I16x8_Extmul_Low_I8x16_S,
        &op_I16x8_Extmul_High_I8x16_S,
        &op_I16x8_Extmul_Low_I8x16_U,
        &op_I16x8_Extmul_High_I8x16_U,
        &op_I32x4_Abs,
        &op_I32x4_Neg,
        &op_I32x4_AllTrue,
        &op_I32x4_Bitmask,
        &op_I32x4_Extend_Low_I16x8_S,
        &op_I32x4_Extend_High_I16x8_S,
        &op_I32x4_Extend_Low_I16x8_U,
        &op_I32x4_Extend_High_I16x8_U,
        &op_I32x4_Shl,
        &op_I32x4_Shr_S,
        &op_I32x4_Shr_U,
        &op_I32x4_Add,
        &op_I32x4_Sub,
        &op_I32x4_Mul,
        &op_I32x4_Min_S,
        &op_I32x4_Min_U,
        &op_I32x4_Max_S,
        &op_I32x4_Max_U,
        &op_I32x4_Dot_I16x8_S,
        &op_I32x4_Extmul_Low_I16x8_S,
        &op_I32x4_Extmul_High_I16x8_S,
        &op_I32x4_Extmul_Low_I16x8_U,
        &op_I32x4_Extmul_High_I16x8_U,
        &op_I64x2_Abs,
        &op_I64x2_Neg,
        &op_I64x2_AllTrue,
        &op_I64x2_Bitmask,
        &op_I64x2_Extend_Low_I32x4_S,
        &op_I64x2_Extend_High_I32x4_S,
        &op_I64x2_Extend_Low_I32x4_U,
        &op_I64x2_Extend_High_I32x4_U,
        &op_I64x2_Shl,
        &op_I64x2_Shr_S,
        &op_I64x2_Shr_U,
        &op_I64x2_Add,
        &op_I64x2_Sub,
        &op_I64x2_Mul,
        &op_I64x2_EQ,
        &op_I64x2_NE,
        &op_I64x2_LT_S,
        &op_I64x2_GT_S,
        &op_I64x2_LE_S,
        &op_I64x2_GE_S,
        &op_I64x2_Extmul_Low_I32x4_S,
        &op_I64x2_Extmul_High_I32x4_S,
        &op_I64x2_Extmul_Low_I32x4_U,
        &op_I64x2_Extmul_High_I32x4_U,
        &op_F32x4_Abs,
        &op_F32x4_Neg,
        &op_F32x4_Sqrt,
        &op_F32x4_Add,
        &op_F32x4_Sub,
        &op_F32x4_Mul,
        &op_F32x4_Div,
        &op_F32x4_Min,
        &op_F32x4_Max,
        &op_F32x4_PMin,
        &op_F32x4_PMax,
        &op_F64x2_Abs,
        &op_F64x2_Neg,
        &op_F64x2_Sqrt,
        &op_F64x2_Add,
        &op_F64x2_Sub,
        &op_F64x2_Mul,
        &op_F64x2_Div,
        &op_F64x2_Min,
        &op_F64x2_Max,
        &op_F64x2_PMin,
        &op_F64x2_PMax,
        &op_F32x4_Trunc_Sat_F32x4_S,
        &op_F32x4_Trunc_Sat_F32x4_U,
        &op_F32x4_Convert_I32x4_S,
        &op_F32x4_Convert_I32x4_U,
        &op_I32x4_Trunc_Sat_F64x2_S_Zero,
        &op_I32x4_Trunc_Sat_F64x2_U_Zero,
        &op_F64x2_Convert_Low_I32x4_S,
        &op_F64x2_Convert_Low_I32x4_U,
    };

    fn run(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn lookup(opcode: Opcode) InstructionFunc {
        return opcodeToFuncTable[@intFromEnum(opcode)];
    }

    const OpHelpers = struct {
        const NanPropagateOp = enum {
            Min,
            Max,
        };

        fn propagateNanWithOp(comptime op: NanPropagateOp, v1: anytype, v2: @TypeOf(v1)) @TypeOf(v1) {
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

        fn truncateTo(comptime T: type, value: anytype) !T {
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
                if (@typeInfo(T).Int.bits < @typeInfo(@TypeOf(truncated)).Float.bits) {
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

        fn saturatedTruncateTo(comptime T: type, value: anytype) T {
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
                if (@typeInfo(T).Int.bits < @typeInfo(@TypeOf(truncated)).Float.bits) {
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

        fn loadFromMem(comptime T: type, stack: *Stack, offset_from_memarg: usize) TrapError!T {
            const offset_from_stack: i64 = stack.popIndexType();
            if (offset_from_stack < 0) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const store: *Store = &stack.topFrame().module_instance.store;
            const memory: *const MemoryInstance = store.getMemory(0);
            const offset: usize = offset_from_memarg + @as(usize, @intCast(offset_from_stack));

            const bit_count = @bitSizeOf(T);
            const read_type = switch (bit_count) {
                8 => u8,
                16 => u16,
                32 => u32,
                64 => u64,
                128 => u128,
                else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
            };

            const end = offset + (bit_count / 8);

            const buffer = memory.buffer();
            if (buffer.len < end) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const mem = buffer[offset..end];
            const byte_count = bit_count / 8;
            const value = std.mem.readInt(read_type, mem[0..byte_count], .little);
            return @as(T, @bitCast(value));
        }

        fn loadArrayFromMem(comptime read_type: type, comptime out_type: type, comptime array_len: usize, store: *Store, offset_from_memarg: usize, offset_from_stack: i32) ![array_len]out_type {
            if (offset_from_stack < 0) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const memory: *const MemoryInstance = store.getMemory(0);
            const offset: usize = offset_from_memarg + @as(usize, @intCast(offset_from_stack));

            const byte_count = @sizeOf(read_type);
            const end = offset + (byte_count * array_len);

            const buffer = memory.buffer();
            if (buffer.len < end) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            var ret: [array_len]out_type = undefined;
            const mem = buffer[offset..end];
            var i: usize = 0;
            while (i < array_len) : (i += 1) {
                const value_start = i * byte_count;
                const value_end = value_start + byte_count;
                ret[i] = std.mem.readInt(read_type, mem[value_start..value_end][0..byte_count], .little);
            }
            return ret;
        }

        fn storeInMem(value: anytype, stack: *Stack, offset_from_memarg: usize) !void {
            const offset_from_stack: i64 = stack.popIndexType();
            if (offset_from_stack < 0) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const store: *Store = &stack.topFrame().module_instance.store;
            const memory: *MemoryInstance = store.getMemory(0);
            const offset: usize = offset_from_memarg + @as(usize, @intCast(offset_from_stack));

            const bit_count = @bitSizeOf(@TypeOf(value));
            const write_type = switch (bit_count) {
                8 => u8,
                16 => u16,
                32 => u32,
                64 => u64,
                128 => u128,
                else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
            };

            const end = offset + (bit_count / 8);
            const buffer = memory.buffer();

            if (buffer.len < end) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const write_value = @as(write_type, @bitCast(value));

            const mem = buffer[offset..end];
            const byte_count = bit_count / 8;
            std.mem.writeInt(write_type, mem[0..byte_count], write_value, .little);
        }

        fn call(code: *InstructionStreamReader, stack: *Stack, module_instance: *ModuleInstance, func: *const FunctionInstance) !*InstructionStreamReader {
            const functype: *const FunctionTypeDefinition = &module_instance.module_def.types.items[func.type_def_index];
            const param_types: []const ValType = functype.getParams();
            const return_types: []const ValType = functype.getReturns();
            const continuation: u32 = code.programCounter();

            try stack.pushFrame(func, module_instance, param_types, func.local_types.items, functype.calcNumReturns());
            try stack.pushLabel(code.opcode(), @as(u32, @intCast(return_types.len)), continuation);

            DebugTrace.traceFunction(module_instance, stack.num_frames, func.def_index);

            const stackvm: *StackVM = StackVM.fromVM(module_instance.vm);
            var next_code: *InstructionStreamReader = &stackvm.instructions_reader;
            next_code.jump(func.instructions_begin);
            return next_code;
        }

        fn callImport(code: *InstructionStreamReader, stack: *Stack, func: *const FunctionImport) !*InstructionStreamReader {
            switch (func.data) {
                .Host => |data| {
                    const params_len: u32 = @as(u32, @intCast(data.func_def.getParams().len));
                    const returns_len: u32 = @as(u32, @intCast(data.func_def.calcNumReturns()));

                    if (stack.num_values + returns_len < stack.values.len) {
                        const module: *ModuleInstance = stack.topFrame().module_instance;
                        const params = stack.values[stack.num_values - params_len .. stack.num_values];
                        const returns_temp = stack.values[stack.num_values .. stack.num_values + returns_len];

                        DebugTrace.traceHostFunction(module, stack.num_frames + 1, func.name);

                        data.callback(data.userdata, module, params.ptr, returns_temp.ptr);

                        stack.num_values = (stack.num_values - params_len) + returns_len;
                        const returns_dest = stack.values[stack.num_values - returns_len .. stack.num_values];

                        assert(@intFromPtr(returns_dest.ptr) < @intFromPtr(returns_temp.ptr));
                        std.mem.copyForwards(Val, returns_dest, returns_temp);

                        return code;
                    } else {
                        return error.TrapStackExhausted;
                    }
                },
                .Wasm => |data| {
                    var stack_vm: *StackVM = StackVM.fromVM(data.module_instance.vm);
                    const func_instance: *const FunctionInstance = &stack_vm.functions.items[data.index];
                    return try call(code, stack, data.module_instance, func_instance);
                },
            }
        }

        fn branch(code: *InstructionStreamReader, stack: *Stack, label_id: u32) ?*InstructionStreamReader {
            const label: *const Label = stack.findLabel(label_id);
            const frame_label: *const Label = stack.frameLabel();
            // TODO generate BranchToFunctionEnd opcode if this can be statically determined at decode time (or just generate a Return?)
            if (label == frame_label) {
                return stack.popFrame();
            }

            const continuation = label.continuation;

            if (label.is_loop_continuation == false or label_id != 0) {
                const pop_final_label = !label.is_loop_continuation;
                stack.popAllUntilLabelId(label_id, pop_final_label, label.num_returns);
            }

            code.jump(continuation);

            // branching takes care of popping/pushing values so skip the End instruction. Normally we'd also have to read
            // the instruction immediates, but End doesn't have any.
            const opcode: Opcode = code.opcode();
            if (opcode == .Loop) { // TODO double check if we can use label.is_loop_continuation
                code.advance(BlockImmediates);
            } else {
                code.advance(void);
            }

            std.debug.assert(opcode == .End or opcode == .Loop);

            return code;
        }

        const VectorUnaryOp = enum(u8) {
            Ceil,
            Floor,
            Trunc,
            Nearest,
        };

        fn vectorUnOp(comptime T: type, op: VectorUnaryOp, stack: *Stack) void {
            const vec = @as(T, @bitCast(stack.popV128()));
            const type_info = @typeInfo(T).Vector;
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

        fn vectorOr(comptime len: usize, v1: @Vector(len, bool), v2: @Vector(len, bool)) @Vector(len, bool) {
            var arr: [len]bool = undefined;
            for (&arr, 0..) |*v, i| {
                v.* = v1[i] or v2[i];
            }
            return arr;
        }

        fn vectorBinOp(comptime T: type, comptime op: VectorBinaryOp, stack: *Stack) void {
            const type_info = @typeInfo(T).Vector;
            const child_type = type_info.child;
            const v2 = @as(T, @bitCast(stack.popV128()));
            const v1 = @as(T, @bitCast(stack.popV128()));
            const result = switch (op) {
                .Add => blk: {
                    break :blk switch (@typeInfo(child_type)) {
                        .Int => v1 +% v2,
                        .Float => v1 + v2,
                        else => unreachable,
                    };
                },
                .Add_Sat => v1 +| v2,
                .Sub => blk: {
                    break :blk switch (@typeInfo(child_type)) {
                        .Int => v1 -% v2,
                        .Float => v1 - v2,
                        else => unreachable,
                    };
                },
                .Sub_Sat => v1 -| v2,
                .Mul => blk: {
                    break :blk switch (@typeInfo(child_type)) {
                        .Int => v1 *% v2,
                        .Float => v1 * v2,
                        else => unreachable,
                    };
                },
                .Div => v1 / v2,
                .Min => blk: {
                    break :blk switch (@typeInfo(child_type)) {
                        .Int => @min(v1, v2),
                        .Float => blk2: {
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
                        .Int => @max(v1, v2),
                        .Float => blk2: {
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

        fn vectorAbs(comptime T: type, stack: *Stack) void {
            const type_info = @typeInfo(T).Vector;
            const child_type = type_info.child;
            const vec = @as(T, @bitCast(stack.popV128()));
            var arr: [type_info.len]child_type = undefined;
            for (&arr, 0..) |*v, i| {
                v.* = @as(child_type, @bitCast(@abs(vec[i])));
            }
            const abs: T = arr;
            stack.pushV128(@as(v128, @bitCast(abs)));
        }

        fn vectorAvgrU(comptime T: type, stack: *Stack) void {
            const type_info = @typeInfo(T).Vector;
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

        fn vectorBoolOp(comptime T: type, comptime op: VectorBoolOp, stack: *Stack) void {
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
            const vec_type_info = @typeInfo(T).Vector;

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

        fn vectorShift(comptime T: type, comptime direction: VectorShiftDirection, stack: *Stack) void {
            const shift_unsafe: i32 = stack.popI32();
            const vec = @as(T, @bitCast(stack.popV128()));
            const shift_safe = std.math.mod(i32, shift_unsafe, @bitSizeOf(@typeInfo(T).Vector.child)) catch unreachable;
            const shift_fn = if (direction == .Left) std.math.shl else std.math.shr;
            const shifted = shift_fn(T, vec, shift_safe);
            stack.pushV128(@as(v128, @bitCast(shifted)));
        }

        fn vectorAllTrue(comptime T: type, vec: v128) i32 {
            const v = @as(T, @bitCast(vec));
            const zeroes: T = @splat(0);
            const bools = v != zeroes;
            const any_true: bool = @reduce(.And, bools);
            return if (any_true) 1 else 0;
        }

        fn vectorBitmask(comptime T: type, vec: v128) i32 {
            switch (@typeInfo(T)) {
                .Vector => |vec_type_info| {
                    switch (@typeInfo(vec_type_info.child)) {
                        .Int => {},
                        else => @compileError("Vector child type must be an int"),
                    }
                },
                else => @compileError("Expected T to be a vector type"),
            }

            const child_type: type = @typeInfo(T).Vector.child;

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
                const vec_len = @typeInfo(T).Vector.len;
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

        fn vectorLoadLane(comptime T: type, code: *InstructionStreamReader, stack: *Stack) !void {
            const vec_type_info = @typeInfo(T).Vector;

            var vec = @as(T, @bitCast(stack.popV128()));
            const immediate: *const MemoryOffsetAndLaneImmediates = code.immediates(MemoryOffsetAndLaneImmediates);
            const scalar = try loadFromMem(vec_type_info.child, stack, immediate.offset);
            vec[immediate.laneidx] = scalar;
            stack.pushV128(@as(v128, @bitCast(vec)));
            code.advance(MemoryOffsetAndLaneImmediates);
        }

        fn vectorLoadExtend(comptime mem_type: type, comptime extend_type: type, comptime len: usize, mem_offset: usize, stack: *Stack) !void {
            const offset_from_stack: i32 = stack.popI32();
            const array: [len]extend_type = try OpHelpers.loadArrayFromMem(mem_type, extend_type, len, &stack.topFrame().module_instance.store, mem_offset, offset_from_stack);
            const vec: @Vector(len, extend_type) = array;
            stack.pushV128(@as(v128, @bitCast(vec)));
        }

        fn vectorLoadLaneZero(comptime T: type, code: *InstructionStreamReader, stack: *Stack) !void {
            const vec_type_info = @typeInfo(T).Vector;

            const mem_offset: u64 = code.immediates(u64).*;
            const scalar = try loadFromMem(vec_type_info.child, stack, mem_offset);
            var vec: T = @splat(0);
            vec[0] = scalar;
            stack.pushV128(@as(v128, @bitCast(vec)));
            code.advance(u64);
        }

        fn vectorStoreLane(comptime T: type, code: *InstructionStreamReader, stack: *Stack) !void {
            const vec = @as(T, @bitCast(stack.popV128()));
            const immediate: *const MemoryOffsetAndLaneImmediates = code.immediates(MemoryOffsetAndLaneImmediates);
            const scalar = vec[immediate.laneidx];
            try storeInMem(scalar, stack, immediate.offset);
            stack.pushV128(@as(v128, @bitCast(vec)));
            code.advance(MemoryOffsetAndLaneImmediates);
        }

        fn vectorExtractLane(comptime T: type, lane: u32, stack: *Stack) void {
            const vec = @as(T, @bitCast(stack.popV128()));
            const lane_value = vec[lane];

            const child_type = @typeInfo(T).Vector.child;
            switch (child_type) {
                i8, u8, i16, u16, i32 => stack.pushI32(lane_value),
                i64 => stack.pushI64(lane_value),
                f32 => stack.pushF32(lane_value),
                f64 => stack.pushF64(lane_value),
                else => unreachable,
            }
        }

        fn vectorReplaceLane(comptime T: type, lane: u32, stack: *Stack) void {
            const child_type = @typeInfo(T).Vector.child;
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

        fn vectorAddPairwise(comptime in_type: type, comptime out_type: type, stack: *Stack) void {
            const out_info = @typeInfo(out_type).Vector;

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

        fn vectorMulPairwise(comptime in_type: type, comptime out_type: type, side: OpHelpers.VectorSide, stack: *Stack) void {
            const info_out = @typeInfo(out_type).Vector;

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

        fn vectorExtend(comptime in_type: type, comptime out_type: type, comptime side: VectorSide, stack: *Stack) void {
            const in_info = @typeInfo(in_type).Vector;
            const out_info = @typeInfo(out_type).Vector;
            const side_offset = if (side == .Low) 0 else in_info.len / 2;

            const vec = @as(in_type, @bitCast(stack.popV128()));
            var arr: [out_info.len]out_info.child = undefined;
            for (&arr, 0..) |*v, i| {
                v.* = vec[i + side_offset];
            }
            const extended: out_type = arr;
            stack.pushV128(@as(v128, @bitCast(extended)));
        }

        fn saturate(comptime T: type, v: anytype) @TypeOf(v) {
            switch (@typeInfo(T)) {
                .Int => {},
                else => unreachable,
            }
            const min = std.math.minInt(T);
            const max = std.math.maxInt(T);
            const clamped = std.math.clamp(v, min, max);
            return clamped;
        }

        fn vectorConvert(comptime in_type: type, comptime out_type: type, comptime side: VectorSide, convert: VectorConvert, stack: *Stack) void {
            const in_info = @typeInfo(in_type).Vector;
            const out_info = @typeInfo(out_type).Vector;
            const side_offset = if (side == .Low) 0 else in_info.len / 2;

            const vec_in = @as(in_type, @bitCast(stack.popV128()));
            var arr: [out_info.len]out_info.child = undefined;
            for (arr, 0..) |_, i| {
                const v: in_info.child = if (i < in_info.len) vec_in[i + side_offset] else 0;
                switch (@typeInfo(out_info.child)) {
                    .Int => arr[i] = blk: {
                        if (convert == .SafeCast) {
                            break :blk @as(out_info.child, @intFromFloat(v));
                        } else {
                            break :blk saturatedTruncateTo(out_info.child, v);
                        }
                    },
                    .Float => arr[i] = @as(out_info.child, @floatFromInt(v)),
                    else => unreachable,
                }
            }
            const vec_out: out_type = arr;
            stack.pushV128(@as(v128, @bitCast(vec_out)));
        }

        fn vectorNarrowingSaturate(comptime in_type: type, comptime out_type: type, vec: in_type) out_type {
            const in_info = @typeInfo(in_type).Vector;
            const out_info = @typeInfo(out_type).Vector;
            const T: type = out_info.child;

            std.debug.assert(out_info.len == in_info.len);

            var arr: [out_info.len]T = undefined;
            for (&arr, 0..) |*v, i| {
                v.* = @as(T, @intCast(std.math.clamp(vec[i], std.math.minInt(T), std.math.maxInt(T))));
            }
            return arr;
        }

        fn vectorNarrow(comptime in_type: type, comptime out_type: type, stack: *Stack) void {
            const out_info = @typeInfo(out_type).Vector;

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

    fn preamble(name: []const u8, code: *InstructionStreamReader, stack: *Stack) TrapError!void {
        const root_module_instance: *ModuleInstance = stack.frames[0].module_instance;
        const root_stackvm: *StackVM = StackVM.fromVM(root_module_instance.vm);

        if (metering.enabled) {
            if (root_stackvm.meter_state.enabled) {
                const meter = metering.reduce(root_stackvm.meter_state.meter, code.opcode());
                root_stackvm.meter_state.meter = meter;
                if (meter == 0) {
                    root_stackvm.meter_state.pc = code.pc();
                    root_stackvm.meter_state.opcode = code.opcode();
                    return metering.MeteringTrapError.TrapMeterExceeded;
                }
            }
        }

        if (config.enable_debug_trap) {
            if (root_stackvm.debug_state) |*debug_state| {
                if (debug_state.trap_counter > 0) {
                    debug_state.trap_counter -= 1;
                    if (debug_state.trap_counter == 0) {
                        debug_state.pc = code.programCounter();
                        return error.TrapDebug;
                    }
                }
            }
        }

        DebugTraceStackVM.traceInstruction(name, code.programCounter(), stack);
    }

    fn op_Invalid(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Invalid", code, stack);
        unreachable;
    }

    fn op_Unreachable(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Unreachable", code, stack);
        return error.TrapUnreachable;
    }

    fn op_DebugTrap(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("DebugTrap", code, stack);
        const root_module_instance: *ModuleInstance = stack.frames[0].module_instance;
        const stack_vm = StackVM.fromVM(root_module_instance.vm);

        // TODO make sure to save pointer to which module instance was trapped in
        std.debug.assert(stack_vm.debug_state != null);
        const pc: usize = code.programCounter();
        stack_vm.debug_state.?.pc = pc;
        stack_vm.debug_state.?.module_instance = stack.topFrame().module_instance;

        return error.TrapDebug;
    }

    fn op_Noop(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Noop", code, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Block(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Block", code, stack);
        const immediates = code.immediates(BlockImmediates);
        try stack.pushLabel(code.opcode(), immediates.num_returns, immediates.continuation);
        code.advance(BlockImmediates);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Loop(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Loop", code, stack);
        const immediates = code.immediates(BlockImmediates);
        try stack.pushLabel(code.opcode(), immediates.num_returns, immediates.continuation);
        code.advance(BlockImmediates);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_If(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("If", code, stack);

        const immediates = code.immediates(IfImmediates);
        const condition = stack.popI32();
        if (condition != 0) {
            try stack.pushLabel(code.opcode(), immediates.num_returns, immediates.end_continuation);
            code.advance(IfImmediates);
        } else {
            try stack.pushLabel(code.opcode(), immediates.num_returns, immediates.end_continuation);
            code.jump(immediates.else_continuation);

            const opcode = code.opcode();
            std.debug.assert(opcode == .Else);
            code.advance(IfImmediates); // TODO ElseImmediates?
        }

        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_IfNoElse(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("IfNoElse", code, stack);

        const immediates = code.immediates(IfImmediates);
        const condition = stack.popI32();
        if (condition != 0) {
            try stack.pushLabel(code.opcode(), immediates.num_returns, immediates.end_continuation);
            code.advance(IfImmediates);
        } else {
            code.jump(immediates.else_continuation);
            const opcode = code.opcode();
            std.debug.assert(opcode == .End);
            code.advance(void); // skip the end opcode
        }

        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    // TODO OPTIMIZE: why does the Else have If immediates?
    fn op_Else(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Else", code, stack);
        // getting here means we reached the end of the if opcode chain, so skip to the true end opcode
        const immediates = code.immediates(IfImmediates);
        const next_pc: u32 = immediates.end_continuation;

        code.jump(next_pc);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_End(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("End", code, stack);

        // TODO - this instruction tries to determine at runtime what behavior to take, but we can
        // probably determine this in the decode phase and split into 2 different end instructions
        // to avoid branching. (End_Label vs End_Frame)

        var next_code: *InstructionStreamReader = undefined;

        // determine if this is a a scope or function call exit
        const top_label: *const Label = stack.topLabel();
        const frame_label: *const Label = stack.frameLabel();
        if (top_label != frame_label) {
            // Since the only values on the stack should be the returns from the block, we just pop the
            // label, which leaves the value stack alone.
            stack.popLabel();

            next_code = code;
            next_code.advance(void);
        } else {
            next_code = stack.popFrame() orelse return;
        }

        try @call(.always_tail, InstructionFuncs.lookup(next_code.opcode()), .{ next_code, stack });
    }

    fn op_Branch(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Branch", code, stack);
        const label_id: u32 = code.immediates(u32).*;
        const next: *InstructionStreamReader = OpHelpers.branch(code, stack, label_id) orelse return;
        try @call(.always_tail, InstructionFuncs.lookup(next.opcode()), .{ next, stack });
    }

    fn op_Branch_If(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Branch_If", code, stack);
        const label_id: u32 = code.immediates(u32).*;

        var next: *InstructionStreamReader = undefined;
        const v = stack.popI32();
        if (v != 0) {
            next = OpHelpers.branch(code, stack, label_id) orelse return;
        } else {
            next = code;
            code.advance(u32);
        }
        try @call(.always_tail, InstructionFuncs.lookup(next.opcode()), .{ next, stack });
    }

    fn op_Branch_Table(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Branch_Table", code, stack);
        const module_instance: *const ModuleInstance = stack.topFrame().module_instance;
        const all_branch_table_immediates: []const BranchTableImmediates = stack.topFrame().module_instance.module_def.code.branch_table.items;
        const immediate_index: u32 = code.immediates(u32).*;

        const immediates: BranchTableImmediates = all_branch_table_immediates[immediate_index];
        const table: []const u32 = immediates.getLabelIds(module_instance.module_def.*);

        const label_index = stack.popI32();
        const label_id: u32 = if (label_index >= 0 and label_index < table.len) table[@as(usize, @intCast(label_index))] else immediates.fallback_id;
        const next: *InstructionStreamReader = OpHelpers.branch(code, stack, label_id) orelse return;

        try @call(.always_tail, InstructionFuncs.lookup(next.opcode()), .{ next, stack });
    }

    fn op_Return(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Return", code, stack);
        const next: *InstructionStreamReader = stack.popFrame() orelse return;
        try @call(.always_tail, InstructionFuncs.lookup(next.opcode()), .{ next, stack });
    }

    // TODO split into 2 ops - Call and Call_Import to avoid the branch
    fn op_Call(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Call", code, stack);

        const func_index: u32 = code.immediates(u32).*;
        code.advance(u32); // OpHelpers.call() needs to record the continuation to the next opcode

        const module_instance: *ModuleInstance = stack.topFrame().module_instance;
        const store: *const Store = &module_instance.store;
        const stack_vm = StackVM.fromVM(module_instance.vm);

        var next: *InstructionStreamReader = undefined;
        if (func_index >= store.imports.functions.items.len) {
            const func_instance_index = func_index - store.imports.functions.items.len;
            const func: *const FunctionInstance = &stack_vm.functions.items[@as(usize, @intCast(func_instance_index))];
            next = try OpHelpers.call(code, stack, module_instance, func);
        } else {
            const func_import = &store.imports.functions.items[func_index];
            next = try OpHelpers.callImport(code, stack, func_import);
        }

        try @call(.always_tail, InstructionFuncs.lookup(next.opcode()), .{ next, stack });
    }

    fn op_Call_Indirect(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Call_Indirect", code, stack);

        const current_module: *ModuleInstance = stack.topFrame().module_instance;
        const immediates: *const CallIndirectImmediates = code.immediates(CallIndirectImmediates);
        code.advance(CallIndirectImmediates); // OpHelpers.call() needs to record the continuation to the next opcode
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
        var call_stackvm = StackVM.fromVM(call_module.vm);

        var next: *InstructionStreamReader = undefined;
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
            next = try OpHelpers.call(code, stack, call_module, func);
        } else {
            var func_import: *const FunctionImport = &call_store.imports.functions.items[func_index];
            const func_type_def: *const FunctionTypeDefinition = &call_module.module_def.types.items[immediates.type_index];
            if (func_import.isTypeSignatureEql(func_type_def) == false) {
                return error.TrapIndirectCallTypeMismatch;
            }
            next = try OpHelpers.callImport(code, stack, func_import);
        }

        try @call(.always_tail, InstructionFuncs.lookup(next.opcode()), .{ next, stack });
    }

    fn op_Drop(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Drop", code, stack);
        _ = stack.popValue();
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Select(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Select", code, stack);

        const boolean: i32 = stack.popI32();
        const v2: Val = stack.popValue();
        const v1: Val = stack.popValue();

        if (boolean != 0) {
            stack.pushValue(v1);
        } else {
            stack.pushValue(v2);
        }

        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Select_T(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Select_T", code, stack);

        const boolean: i32 = stack.popI32();
        const v2: Val = stack.popValue();
        const v1: Val = stack.popValue();

        if (boolean != 0) {
            stack.pushValue(v1);
        } else {
            stack.pushValue(v2);
        }

        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Local_Get(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Local_Get", code, stack);
        try stack.checkExhausted(1);
        const locals_index: u32 = code.immediates(u32).*;
        const frame: *const CallFrame = stack.topFrame();
        const v: Val = frame.locals[locals_index];
        stack.pushValue(v);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Local_Set(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Local_Set", code, stack);

        const locals_index: u32 = code.immediates(u32).*;
        code.advance(u32);
        var frame: *CallFrame = stack.topFrame();
        const v: Val = stack.popValue();
        frame.locals[locals_index] = v;
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Local_Tee(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Local_Tee", code, stack);
        const locals_index: u32 = code.immediates(u32).*;
        var frame: *CallFrame = stack.topFrame();
        const v: Val = stack.topValue();
        frame.locals[locals_index] = v;
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Global_Get(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Global_Get", code, stack);
        try stack.checkExhausted(1);
        const global_index: u32 = code.immediates(u32).*;
        const global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        stack.pushValue(global.value);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Global_Set(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Global_Set", code, stack);
        const global_index: u32 = code.immediates(u32).*;
        const global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        global.value = stack.popValue();
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Table_Get(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Table_Get", code, stack);
        const table_index: u32 = code.immediates(u32).*;
        const table: *const TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const index: i32 = stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        const ref = table.refs.items[@as(usize, @intCast(index))];
        stack.pushValue(ref);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Table_Set(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Table_Set", code, stack);
        const table_index: u32 = code.immediates(u32).*;
        var table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const ref = stack.popValue();
        const index: i32 = stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        table.refs.items[@as(usize, @intCast(index))] = ref;
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Load(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Load", code, stack);
        const value: i32 = try OpHelpers.loadFromMem(i32, stack, code.immediates(u64).*);
        stack.pushI32(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Load(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Load", code, stack);
        const value: i64 = try OpHelpers.loadFromMem(i64, stack, code.immediates(u64).*);
        stack.pushI64(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Load(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Load", code, stack);
        const value: f32 = try OpHelpers.loadFromMem(f32, stack, code.immediates(u64).*);
        stack.pushF32(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Load(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Load", code, stack);
        const value: f64 = try OpHelpers.loadFromMem(f64, stack, code.immediates(u64).*);
        stack.pushF64(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Load8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Load8_S", code, stack);
        const value: i32 = try OpHelpers.loadFromMem(i8, stack, code.immediates(u64).*);
        stack.pushI32(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Load8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Load8_U", code, stack);
        const value: u32 = try OpHelpers.loadFromMem(u8, stack, code.immediates(u64).*);
        stack.pushI32(@as(i32, @bitCast(value)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Load16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Load16_S", code, stack);
        const value: i32 = try OpHelpers.loadFromMem(i16, stack, code.immediates(u64).*);
        stack.pushI32(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Load16_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Load16_U", code, stack);
        const value: u32 = try OpHelpers.loadFromMem(u16, stack, code.immediates(u64).*);
        stack.pushI32(@as(i32, @bitCast(value)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Load8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Load8_S", code, stack);
        const value: i64 = try OpHelpers.loadFromMem(i8, stack, code.immediates(u64).*);
        stack.pushI64(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Load8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Load8_U", code, stack);
        const value: u64 = try OpHelpers.loadFromMem(u8, stack, code.immediates(u64).*);
        stack.pushI64(@as(i64, @bitCast(value)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Load16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Load16_S", code, stack);
        const value: i64 = try OpHelpers.loadFromMem(i16, stack, code.immediates(u64).*);
        stack.pushI64(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Load16_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Load16_U", code, stack);
        const value: u64 = try OpHelpers.loadFromMem(u16, stack, code.immediates(u64).*);
        stack.pushI64(@as(i64, @bitCast(value)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Load32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Load32_S", code, stack);
        const value: i64 = try OpHelpers.loadFromMem(i32, stack, code.immediates(u64).*);
        stack.pushI64(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Load32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Load32_U", code, stack);
        const value: u64 = try OpHelpers.loadFromMem(u32, stack, code.immediates(u64).*);
        stack.pushI64(@as(i64, @bitCast(value)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Store(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Store", code, stack);
        const value: i32 = stack.popI32();
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Store(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Store", code, stack);
        const value: i64 = stack.popI64();
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Store(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Store", code, stack);
        const value: f32 = stack.popF32();
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Store(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Store", code, stack);
        const value: f64 = stack.popF64();
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Store8(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Store8", code, stack);
        const value: i8 = @as(i8, @truncate(stack.popI32()));
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Store16(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Store16", code, stack);
        const value: i16 = @as(i16, @truncate(stack.popI32()));
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Store8(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Store8", code, stack);
        const value: i8 = @as(i8, @truncate(stack.popI64()));
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Store16(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Store16", code, stack);
        const value: i16 = @as(i16, @truncate(stack.popI64()));
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Store32(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Store32", code, stack);
        const value: i32 = @as(i32, @truncate(stack.popI64()));
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Memory_Size(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Memory_Size", code, stack);
        try stack.checkExhausted(1);
        const memory_index: usize = 0;
        var memory_instance: *const MemoryInstance = stack.topFrame().module_instance.store.getMemory(memory_index);

        switch (memory_instance.limits.indexType()) {
            .I32 => stack.pushI32(@intCast(memory_instance.size())),
            .I64 => stack.pushI64(@intCast(memory_instance.size())),
            else => unreachable,
        }

        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Memory_Grow(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Memory_Grow", code, stack);
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
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Const(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Const", code, stack);
        try stack.checkExhausted(1);
        const v: i32 = code.immediates(i32).*;
        stack.pushI32(v);
        code.advance(i32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Const(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Const", code, stack);
        try stack.checkExhausted(1);
        const v: i64 = code.immediates(i64).*;
        stack.pushI64(v);
        code.advance(i64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Const(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Const", code, stack);
        try stack.checkExhausted(1);
        const v: f32 = code.immediates(f32).*;
        stack.pushF32(v);
        code.advance(f32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Const(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Const", code, stack);
        try stack.checkExhausted(1);
        const v: f64 = code.immediates(f64).*;
        stack.pushF64(v);
        code.advance(f64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Eqz(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Eqz", code, stack);
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 == 0) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Eq(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Eq", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_NE", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_LT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_LT_S", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_LT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_LT_U", code, stack);
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_GT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_GT_S", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_GT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_GT_U", code, stack);
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_LE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_LE_S", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_LE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_LE_U", code, stack);
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_GE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_GE_S", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_GE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_GE_U", code, stack);
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Eqz(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Eqz", code, stack);
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 == 0) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Eq(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Eq", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_NE", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_LT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_LT_S", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_LT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_LT_U", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_GT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_GT_S", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_GT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_GT_U", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_LE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_LE_S", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_LE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_LE_U", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_GE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_GE_S", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_GE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_GE_U", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const result: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_EQ", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_NE", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_LT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_LT", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_GT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_GT", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_LE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_LE", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_GE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_GE", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_EQ", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 == v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_NE", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 != v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_LT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_LT", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 < v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_GT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_GT", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 > v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_LE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_LE", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 <= v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_GE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_GE", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value: i32 = if (v1 >= v2) 1 else 0;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Clz(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Clz", code, stack);
        const v: i32 = stack.popI32();
        const num_zeroes = @clz(v);
        stack.pushI32(num_zeroes);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Ctz(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Ctz", code, stack);
        const v: i32 = stack.popI32();
        const num_zeroes = @ctz(v);
        stack.pushI32(num_zeroes);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Popcnt(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Popcnt", code, stack);
        const v: i32 = stack.popI32();
        const num_bits_set = @popCount(v);
        stack.pushI32(num_bits_set);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Add", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result = v1 +% v2;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Sub", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const result = v1 -% v2;
        stack.pushI32(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Mul", code, stack);
        const v2: i32 = stack.popI32();
        const v1: i32 = stack.popI32();
        const value = v1 *% v2;
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Div_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Div_S", code, stack);
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
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Div_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Div_U", code, stack);
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
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Rem_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Rem_S", code, stack);
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
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Rem_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Rem_U", code, stack);
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
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_And(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_And", code, stack);
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(v1 & v2));
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Or(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Or", code, stack);
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(v1 | v2));
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Xor(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Xor", code, stack);
        const v2: u32 = @as(u32, @bitCast(stack.popI32()));
        const v1: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(v1 ^ v2));
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Shl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Shl", code, stack);
        const shift_unsafe: i32 = stack.popI32();
        const int: i32 = stack.popI32();
        const shift: i32 = try std.math.mod(i32, shift_unsafe, 32);
        const value = std.math.shl(i32, int, shift);
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Shr_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Shr_S", code, stack);
        const shift_unsafe: i32 = stack.popI32();
        const int: i32 = stack.popI32();
        const shift = try std.math.mod(i32, shift_unsafe, 32);
        const value = std.math.shr(i32, int, shift);
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Shr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Shr_U", code, stack);
        const shift_unsafe: u32 = @as(u32, @bitCast(stack.popI32()));
        const int: u32 = @as(u32, @bitCast(stack.popI32()));
        const shift = try std.math.mod(u32, shift_unsafe, 32);
        const value = @as(i32, @bitCast(std.math.shr(u32, int, shift)));
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Rotl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Rotl", code, stack);
        const rot: u32 = @as(u32, @bitCast(stack.popI32()));
        const int: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(std.math.rotl(u32, int, rot)));
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Rotr(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Rotr", code, stack);
        const rot: u32 = @as(u32, @bitCast(stack.popI32()));
        const int: u32 = @as(u32, @bitCast(stack.popI32()));
        const value = @as(i32, @bitCast(std.math.rotr(u32, int, rot)));
        stack.pushI32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Clz(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Clz", code, stack);
        const v: i64 = stack.popI64();
        const num_zeroes = @clz(v);
        stack.pushI64(num_zeroes);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Ctz(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Ctz", code, stack);
        const v: i64 = stack.popI64();
        const num_zeroes = @ctz(v);
        stack.pushI64(num_zeroes);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Popcnt(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Popcnt", code, stack);
        const v: i64 = stack.popI64();
        const num_bits_set = @popCount(v);
        stack.pushI64(num_bits_set);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Add", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result = v1 +% v2;
        stack.pushI64(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Sub", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result = v1 -% v2;
        stack.pushI64(result);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Mul", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const value = v1 *% v2;
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Div_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Div_S", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const value = std.math.divTrunc(i64, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Div_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Div_U", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value_unsigned = std.math.divFloor(u64, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        const value = @as(i64, @bitCast(value_unsigned));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Rem_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Rem_S", code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const denom: i64 = @intCast(@abs(v2));
        const value = std.math.rem(i64, v1, denom) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Rem_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Rem_U", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value_unsigned = std.math.rem(u64, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        const value = @as(i64, @bitCast(value_unsigned));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_And(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_And", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(v1 & v2));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Or(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Or", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(v1 | v2));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Xor(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Xor", code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(v1 ^ v2));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Shl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Shl", code, stack);
        const shift_unsafe: i64 = stack.popI64();
        const int: i64 = stack.popI64();
        const shift: i64 = try std.math.mod(i64, shift_unsafe, 64);
        const value = std.math.shl(i64, int, shift);
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Shr_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Shr_S", code, stack);
        const shift_unsafe: i64 = stack.popI64();
        const int: i64 = stack.popI64();
        const shift = try std.math.mod(i64, shift_unsafe, 64);
        const value = std.math.shr(i64, int, shift);
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Shr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Shr_U", code, stack);
        const shift_unsafe: u64 = @as(u64, @bitCast(stack.popI64()));
        const int: u64 = @as(u64, @bitCast(stack.popI64()));
        const shift = try std.math.mod(u64, shift_unsafe, 64);
        const value = @as(i64, @bitCast(std.math.shr(u64, int, shift)));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Rotl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Rotl", code, stack);
        const rot: u64 = @as(u64, @bitCast(stack.popI64()));
        const int: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(std.math.rotl(u64, int, rot)));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Rotr(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Rotr", code, stack);
        const rot: u64 = @as(u64, @bitCast(stack.popI64()));
        const int: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(std.math.rotr(u64, int, rot)));
        stack.pushI64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Abs", code, stack);
        const f = stack.popF32();
        const value = @abs(f);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Neg", code, stack);
        const f = stack.popF32();
        stack.pushF32(-f);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Ceil(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Ceil", code, stack);
        const f = stack.popF32();
        const value = @ceil(f);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Floor(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Floor", code, stack);
        const f = stack.popF32();
        const value = @floor(f);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Trunc(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Trunc", code, stack);
        const f = stack.popF32();
        const value = std.math.trunc(f);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Nearest(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Nearest", code, stack);
        const f = stack.popF32();
        var value: f32 = undefined;
        const ceil = @ceil(f);
        const floor = @floor(f);
        if (ceil - f == f - floor) {
            value = if (@mod(ceil, 2) == 0) ceil else floor;
        } else {
            value = @round(f);
        }
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Sqrt(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Sqrt", code, stack);
        const f = stack.popF32();
        const value = std.math.sqrt(f);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Add", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 + v2;
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Sub", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 - v2;
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Mul", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 * v2;
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Div(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Div", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 / v2;
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Min(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Min", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = OpHelpers.propagateNanWithOp(.Min, v1, v2);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Max(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Max", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = OpHelpers.propagateNanWithOp(.Max, v1, v2);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Copysign(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Copysign", code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = std.math.copysign(v1, v2);
        stack.pushF32(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Abs", code, stack);
        const f = stack.popF64();
        const value = @abs(f);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Neg", code, stack);
        const f = stack.popF64();
        stack.pushF64(-f);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Ceil(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Ceil", code, stack);
        const f = stack.popF64();
        const value = @ceil(f);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Floor(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Floor", code, stack);
        const f = stack.popF64();
        const value = @floor(f);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Trunc(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Trunc", code, stack);
        const f = stack.popF64();
        const value = @trunc(f);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Nearest(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Nearest", code, stack);
        const f = stack.popF64();
        var value: f64 = undefined;
        const ceil = @ceil(f);
        const floor = @floor(f);
        if (ceil - f == f - floor) {
            value = if (@mod(ceil, 2) == 0) ceil else floor;
        } else {
            value = @round(f);
        }
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Sqrt(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Sqrt", code, stack);
        const f = stack.popF64();
        const value = std.math.sqrt(f);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Add", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 + v2;
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Sub", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 - v2;
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Mul", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 * v2;
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Div(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Div", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 / v2;
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Min(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Min", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = OpHelpers.propagateNanWithOp(.Min, v1, v2);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Max(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Max", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = OpHelpers.propagateNanWithOp(.Max, v1, v2);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Copysign(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Copysign", code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = std.math.copysign(v1, v2);
        stack.pushF64(value);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Wrap_I64(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Wrap_I64", code, stack);
        const v = stack.popI64();
        const mod = @as(i32, @truncate(v));
        stack.pushI32(mod);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_F32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F32_S", code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(i32, v);
        stack.pushI32(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_F32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F32_U", code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_F64_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F64_S", code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(i32, v);
        stack.pushI32(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_F64_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F64_U", code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Extend_I32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Extend_I32_S", code, stack);
        const v32 = stack.popI32();
        const v64: i64 = v32;
        stack.pushI64(v64);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Extend_I32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Extend_I32_U", code, stack);
        const v32 = stack.popI32();
        const v64: u64 = @as(u32, @bitCast(v32));
        stack.pushI64(@as(i64, @bitCast(v64)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_F32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F32_S", code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(i64, v);
        stack.pushI64(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_F32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F32_U", code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_F64_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F64_S", code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(i64, v);
        stack.pushI64(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_F64_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F64_U", code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Convert_I32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I32_S", code, stack);
        const v = stack.popI32();
        stack.pushF32(@as(f32, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Convert_I32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I32_U", code, stack);
        const v = @as(u32, @bitCast(stack.popI32()));
        stack.pushF32(@as(f32, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Convert_I64_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I64_S", code, stack);
        const v = stack.popI64();
        stack.pushF32(@as(f32, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Convert_I64_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I64_U", code, stack);
        const v = @as(u64, @bitCast(stack.popI64()));
        stack.pushF32(@as(f32, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Demote_F64(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Demote_F64", code, stack);
        const v = stack.popF64();
        stack.pushF32(@as(f32, @floatCast(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Convert_I32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I32_S", code, stack);
        const v = stack.popI32();
        stack.pushF64(@as(f64, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Convert_I32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I32_U", code, stack);
        const v = @as(u32, @bitCast(stack.popI32()));
        stack.pushF64(@as(f64, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Convert_I64_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I64_S", code, stack);
        const v = stack.popI64();
        stack.pushF64(@as(f64, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Convert_I64_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I64_U", code, stack);
        const v = @as(u64, @bitCast(stack.popI64()));
        stack.pushF64(@as(f64, @floatFromInt(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Promote_F32(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Promote_F32", code, stack);
        const v = stack.popF32();
        stack.pushF64(@as(f64, @floatCast(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Reinterpret_F32(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Reinterpret_F32", code, stack);
        const v = stack.popF32();
        stack.pushI32(@as(i32, @bitCast(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Reinterpret_F64(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Reinterpret_F64", code, stack);
        const v = stack.popF64();
        stack.pushI64(@as(i64, @bitCast(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32_Reinterpret_I32(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32_Reinterpret_I32", code, stack);
        const v = stack.popI32();
        stack.pushF32(@as(f32, @bitCast(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64_Reinterpret_I64(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64_Reinterpret_I64", code, stack);
        const v = stack.popI64();
        stack.pushF64(@as(f64, @bitCast(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Extend8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Extend8_S", code, stack);
        const v = stack.popI32();
        const v_truncated = @as(i8, @truncate(v));
        const v_extended: i32 = v_truncated;
        stack.pushI32(v_extended);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Extend16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Extend16_S", code, stack);
        const v = stack.popI32();
        const v_truncated = @as(i16, @truncate(v));
        const v_extended: i32 = v_truncated;
        stack.pushI32(v_extended);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Extend8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Extend8_S", code, stack);
        const v = stack.popI64();
        const v_truncated = @as(i8, @truncate(v));
        const v_extended: i64 = v_truncated;
        stack.pushI64(v_extended);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Extend16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Extend16_S", code, stack);
        const v = stack.popI64();
        const v_truncated = @as(i16, @truncate(v));
        const v_extended: i64 = v_truncated;
        stack.pushI64(v_extended);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Extend32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Extend32_S", code, stack);
        const v = stack.popI64();
        const v_truncated = @as(i32, @truncate(v));
        const v_extended: i64 = v_truncated;
        stack.pushI64(v_extended);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Ref_Null(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Ref_Null", code, stack);
        try stack.checkExhausted(1);
        const valtype = code.immediates(ValType).*;
        const val = try Val.nullRef(valtype);
        stack.pushValue(val);
        code.advance(ValType);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Ref_Is_Null(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Ref_Is_Null", code, stack);
        const val: Val = stack.popValue();
        const boolean: i32 = if (val.isNull()) 1 else 0;
        stack.pushI32(boolean);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Ref_Func(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Ref_Func", code, stack);
        try stack.checkExhausted(1);
        const func_index: u32 = code.immediates(u32).*;
        const val = Val{ .FuncRef = .{ .index = func_index, .module_instance = stack.topFrame().module_instance } };
        stack.pushValue(val);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_Sat_F32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F32_S", code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(i32, v);
        stack.pushI32(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_Sat_F32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F32_U", code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_Sat_F64_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F64_S", code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(i32, v);
        stack.pushI32(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32_Trunc_Sat_F64_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F64_U", code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_Sat_F32_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F32_S", code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(i64, v);
        stack.pushI64(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_Sat_F32_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F32_U", code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_Sat_F64_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F64_S", code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(i64, v);
        stack.pushI64(int);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64_Trunc_Sat_F64_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F64_U", code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Memory_Init(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Memory_Init", code, stack);
        const data_index: u32 = code.immediates(u32).*;
        const data: *const DataDefinition = &stack.topFrame().module_instance.module_def.datas.items[data_index];
        const memory: *MemoryInstance = &stack.topFrame().module_instance.store.memories.items[0];

        const length = stack.popI32();
        const data_offset = stack.popI32();
        const memory_offset = stack.popI32();

        if (length < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }
        if (data.bytes.items.len < data_offset + length or data_offset < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const buffer = memory.buffer();
        if (buffer.len < memory_offset + length or memory_offset < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const data_offset_u32 = @as(u32, @intCast(data_offset));
        const memory_offset_u32 = @as(u32, @intCast(memory_offset));
        const length_u32 = @as(u32, @intCast(length));

        const source = data.bytes.items[data_offset_u32 .. data_offset_u32 + length_u32];
        const destination = buffer[memory_offset_u32 .. memory_offset_u32 + length_u32];
        @memcpy(destination, source);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Data_Drop(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Data_Drop", code, stack);
        const data_index: u32 = code.immediates(u32).*;
        const data: *DataDefinition = &stack.topFrame().module_instance.module_def.datas.items[data_index];
        data.bytes.clearAndFree();
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Memory_Copy(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Memory_Copy", code, stack);
        const memory: *MemoryInstance = &stack.topFrame().module_instance.store.memories.items[0];

        const length_s = stack.popIndexType();
        const source_offset_s = stack.popIndexType();
        const dest_offset_s = stack.popIndexType();

        if (length_s < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const buffer = memory.buffer();
        if (buffer.len < source_offset_s + length_s or source_offset_s < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }
        if (buffer.len < dest_offset_s + length_s or dest_offset_s < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const source_offset = @as(u64, @intCast(source_offset_s));
        const dest_offset = @as(u64, @intCast(dest_offset_s));
        const length = @as(u64, @intCast(length_s));

        const source = buffer[source_offset .. source_offset + length];
        const destination = buffer[dest_offset .. dest_offset + length];

        if (@intFromPtr(destination.ptr) < @intFromPtr(source.ptr)) {
            std.mem.copyForwards(u8, destination, source);
        } else {
            std.mem.copyBackwards(u8, destination, source);
        }
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Memory_Fill(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Memory_Fill", code, stack);
        const memory: *MemoryInstance = &stack.topFrame().module_instance.store.memories.items[0];

        const length_s: i64 = stack.popIndexType();
        const value: u8 = @as(u8, @truncate(@as(u32, @bitCast(stack.popI32()))));
        const offset_s: i64 = stack.popIndexType();

        if (length_s < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const buffer = memory.buffer();
        if (buffer.len < offset_s + length_s or offset_s < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const offset = @as(u64, @intCast(offset_s));
        const length = @as(u64, @intCast(length_s));

        const destination = buffer[offset .. offset + length];
        @memset(destination, value);

        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Table_Init(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Table_Init", code, stack);
        const pair: *const TablePairImmediates = code.immediates(TablePairImmediates);
        const elem_index = pair.index_x;
        const table_index = pair.index_y;

        const elem: *const ElementInstance = &stack.topFrame().module_instance.store.elements.items[elem_index];
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);

        const length_i32 = stack.popI32();
        const elem_start_index = stack.popI32();
        const table_start_index = stack.popI32();

        if (elem_start_index + length_i32 > elem.refs.items.len or elem_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (table_start_index + length_i32 > table.refs.items.len or table_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (length_i32 < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }

        const elem_begin = @as(usize, @intCast(elem_start_index));
        const table_begin = @as(usize, @intCast(table_start_index));
        const length = @as(usize, @intCast(length_i32));

        const dest: []Val = table.refs.items[table_begin .. table_begin + length];
        const src: []const Val = elem.refs.items[elem_begin .. elem_begin + length];

        @memcpy(dest, src);
        code.advance(TablePairImmediates);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Elem_Drop(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Elem_Drop", code, stack);
        const elem_index: u32 = code.immediates(u32).*;
        var elem: *ElementInstance = &stack.topFrame().module_instance.store.elements.items[elem_index];
        elem.refs.clearAndFree();
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Table_Copy(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Table_Copy", code, stack);
        const pair: *const TablePairImmediates = code.immediates(TablePairImmediates);
        const dest_table_index = pair.index_x;
        const src_table_index = pair.index_y;

        const dest_table: *TableInstance = stack.topFrame().module_instance.store.getTable(dest_table_index);
        const src_table: *const TableInstance = stack.topFrame().module_instance.store.getTable(src_table_index);

        const length_i32 = stack.popI32();
        const src_start_index = stack.popI32();
        const dest_start_index = stack.popI32();

        if (src_start_index + length_i32 > src_table.refs.items.len or src_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (dest_start_index + length_i32 > dest_table.refs.items.len or dest_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (length_i32 < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }

        const dest_begin = @as(usize, @intCast(dest_start_index));
        const src_begin = @as(usize, @intCast(src_start_index));
        const length = @as(usize, @intCast(length_i32));

        const dest: []Val = dest_table.refs.items[dest_begin .. dest_begin + length];
        const src: []const Val = src_table.refs.items[src_begin .. src_begin + length];
        if (dest_start_index <= src_start_index) {
            std.mem.copyForwards(Val, dest, src);
        } else {
            std.mem.copyBackwards(Val, dest, src);
        }
        code.advance(TablePairImmediates);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Table_Grow(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Table_Grow", code, stack);
        const table_index: u32 = code.immediates(u32).*;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const length = @as(u32, @bitCast(stack.popI32()));
        const init_value = stack.popValue();
        const old_length = @as(i32, @intCast(table.refs.items.len));
        const return_value: i32 = if (table.grow(length, init_value)) old_length else -1;
        stack.pushI32(return_value);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Table_Size(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Table_Size", code, stack);
        const table_index: u32 = code.immediates(u32).*;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const length = @as(i32, @intCast(table.refs.items.len));
        stack.pushI32(length);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_Table_Fill(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("Table_Fill", code, stack);
        const table_index: u32 = code.immediates(u32).*;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);

        const length_i32 = stack.popI32();
        const funcref = stack.popValue();
        const dest_table_index = stack.popI32();

        if (dest_table_index + length_i32 > table.refs.items.len or length_i32 < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }

        const dest_begin = @as(usize, @intCast(dest_table_index));
        const length = @as(usize, @intCast(length_i32));

        const dest: []Val = table.refs.items[dest_begin .. dest_begin + length];

        @memset(dest, funcref);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load", code, stack);
        const value: v128 = try OpHelpers.loadFromMem(v128, stack, code.immediates(u64).*);
        stack.pushV128(value);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load8x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load8x8_S", code, stack);
        try OpHelpers.vectorLoadExtend(i8, i16, 8, code.immediates(u64).*, stack);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load8x8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load8x8_S", code, stack);
        try OpHelpers.vectorLoadExtend(u8, i16, 8, code.immediates(u64).*, stack);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load16x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load16x4_S", code, stack);
        try OpHelpers.vectorLoadExtend(i16, i32, 4, code.immediates(u64).*, stack);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load16x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load16x4_U", code, stack);
        try OpHelpers.vectorLoadExtend(u16, i32, 4, code.immediates(u64).*, stack);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load32x2_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load32x2_S", code, stack);
        try OpHelpers.vectorLoadExtend(i32, i64, 2, code.immediates(u64).*, stack);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load32x2_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load32x2_U", code, stack);
        try OpHelpers.vectorLoadExtend(u32, i64, 2, code.immediates(u64).*, stack);
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load8_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load8_Splat", code, stack);
        const scalar = try OpHelpers.loadFromMem(u8, stack, code.immediates(u64).*);
        const vec: u8x16 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load16_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load16_Splat", code, stack);
        const scalar = try OpHelpers.loadFromMem(u16, stack, code.immediates(u64).*);
        const vec: u16x8 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load32_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load32_Splat", code, stack);
        const scalar = try OpHelpers.loadFromMem(u32, stack, code.immediates(u64).*);
        const vec: u32x4 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load64_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load64_Splat", code, stack);
        const scalar = try OpHelpers.loadFromMem(u64, stack, code.immediates(u64).*);
        const vec: u64x2 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Splat", code, stack);
        const scalar = @as(i8, @truncate(stack.popI32()));
        const vec: i8x16 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Splat", code, stack);
        const scalar = @as(i16, @truncate(stack.popI32()));
        const vec: i16x8 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Splat", code, stack);
        const scalar = stack.popI32();
        const vec: i32x4 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Splat", code, stack);
        const scalar = stack.popI64();
        const vec: i64x2 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Splat", code, stack);
        const scalar = stack.popF32();
        const vec: f32x4 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Splat(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Splat", code, stack);
        const scalar = stack.popF64();
        const vec: f64x2 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Extract_Lane_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Extract_Lane_S", code, stack);
        OpHelpers.vectorExtractLane(i8x16, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Extract_Lane_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Extract_Lane_U", code, stack);
        OpHelpers.vectorExtractLane(u8x16, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Replace_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Replace_Lane", code, stack);
        OpHelpers.vectorReplaceLane(i8x16, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extract_Lane_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extract_Lane_S", code, stack);
        OpHelpers.vectorExtractLane(i16x8, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extract_Lane_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extract_Lane_U", code, stack);
        OpHelpers.vectorExtractLane(u16x8, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Replace_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Replace_Lane", code, stack);
        OpHelpers.vectorReplaceLane(i16x8, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extract_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extract_Lane", code, stack);
        OpHelpers.vectorExtractLane(i32x4, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Replace_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Replace_Lane", code, stack);
        OpHelpers.vectorReplaceLane(i32x4, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Extract_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extract_Lane", code, stack);
        OpHelpers.vectorExtractLane(i64x2, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Replace_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Replace_Lane", code, stack);
        OpHelpers.vectorReplaceLane(i64x2, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Extract_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Extract_Lane", code, stack);
        OpHelpers.vectorExtractLane(f32x4, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Replace_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Replace_Lane", code, stack);
        OpHelpers.vectorReplaceLane(f32x4, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Extract_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Extract_Lane", code, stack);
        OpHelpers.vectorExtractLane(f64x2, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Replace_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Replace_Lane", code, stack);
        OpHelpers.vectorReplaceLane(f64x2, code.immediates(u32).*, stack);
        code.advance(u32);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_EQ", code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Eq, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_NE", code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Ne, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_LT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_LT_S", code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_LT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_LT_U", code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_GT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_GT_S", code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_GT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_GT_U", code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_LE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_LE_S", code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_LE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_LE_U", code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_GE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_GE_S", code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_GE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_GE_U", code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_EQ", code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Eq, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_NE", code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Ne, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_LT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_LT_S", code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_LT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_LT_U", code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_GT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_GT_S", code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_GT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_GT_U", code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_LE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_LE_S", code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_LE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_LE_U", code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_GE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_GE_S", code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_GE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_GE_U", code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_EQ", code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Eq, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_NE", code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Ne, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_LT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_LT_S", code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_LT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_LT_U", code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_GT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_GT_S", code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_GT_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_GT_U", code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_LE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_LE_S", code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_LE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_LE_U", code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_GE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_GE_S", code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_GE_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_GE_U", code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_EQ", code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Eq, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_NE", code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Ne, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_LT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_LT", code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_GT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_GT", code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_LE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_LE", code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_GE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_GE", code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_EQ", code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Eq, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_NE", code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Ne, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_LT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_LT", code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_GT(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_GT", code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_LE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_LE", code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_GE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_GE", code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Store(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Store", code, stack);

        const value: v128 = stack.popV128();
        try OpHelpers.storeInMem(value, stack, code.immediates(u64).*);

        code.advance(u64);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Const(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Const", code, stack);
        try stack.checkExhausted(1);
        const v: v128 = code.immediates(v128).*;
        stack.pushV128(v);
        code.advance(v128);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Shuffle(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shuffle", code, stack);
        const v2 = @as(i8x16, @bitCast(stack.popV128()));
        const v1 = @as(i8x16, @bitCast(stack.popV128()));
        const indices: *const [16]u8 = code.immediates([16]u8);

        var concat: [32]i8 = undefined;
        for (concat[0..16], 0..) |_, i| {
            concat[i] = v1[i];
            concat[i + 16] = v2[i];
        }
        const concat_v: @Vector(32, i8) = concat;

        var arr: [16]i8 = undefined;
        for (&arr, 0..) |*v, i| {
            const laneidx = (indices.*)[i];
            v.* = concat_v[laneidx];
        }
        const shuffled: i8x16 = arr;

        stack.pushV128(@as(v128, @bitCast(shuffled)));
        code.advance([16]u8);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Swizzle(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Swizzle", code, stack);
        const indices: i8x16 = @as(i8x16, @bitCast(stack.popV128()));
        const vec: i8x16 = @as(i8x16, @bitCast(stack.popV128()));
        var swizzled: i8x16 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            const value = if (indices[i] >= 0 and indices[i] < 16) vec[@as(usize, @intCast(indices[i]))] else @as(i8, 0);
            swizzled[i] = value;
        }
        stack.pushV128(@as(v128, @bitCast(swizzled)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Not(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Not", code, stack);
        const v = @as(i8x16, @bitCast(stack.popV128()));
        const inverted = ~v;
        stack.pushV128(@as(v128, @bitCast(inverted)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_And(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_And", code, stack);
        OpHelpers.vectorBinOp(i8x16, .And, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_AndNot(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_AndNot", code, stack);
        OpHelpers.vectorBinOp(i8x16, .AndNot, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Or(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Or", code, stack);
        OpHelpers.vectorBinOp(i8x16, .Or, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Xor(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Xor", code, stack);
        OpHelpers.vectorBinOp(i8x16, .Xor, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Bitselect(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Bitselect", code, stack);
        const u1x128 = @Vector(128, u1);
        const c = @as(@Vector(128, bool), @bitCast(stack.popV128()));
        const v2 = @as(u1x128, @bitCast(stack.popV128()));
        const v1 = @as(u1x128, @bitCast(stack.popV128()));
        const v = @select(u1, c, v1, v2);
        stack.pushV128(@as(v128, @bitCast(v)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_AnyTrue(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_AnyTrue", code, stack);
        const v = @as(u128, @bitCast(stack.popV128()));
        const boolean: i32 = if (v != 0) 1 else 0;
        stack.pushI32(boolean);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load8_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load8_Lane", code, stack);
        try OpHelpers.vectorLoadLane(u8x16, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load16_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load16_Lane", code, stack);
        try OpHelpers.vectorLoadLane(u16x8, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load32_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load32_Lane", code, stack);
        try OpHelpers.vectorLoadLane(u32x4, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load64_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load64_Lane", code, stack);
        try OpHelpers.vectorLoadLane(u64x2, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Store8_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Store8_Lane", code, stack);
        try OpHelpers.vectorStoreLane(u8x16, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Store16_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Store16_Lane", code, stack);
        try OpHelpers.vectorStoreLane(u16x8, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Store32_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Store32_Lane", code, stack);
        try OpHelpers.vectorStoreLane(u32x4, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Store64_Lane(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Store64_Lane", code, stack);
        try OpHelpers.vectorStoreLane(u64x2, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load32_Zero(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load32_Zero", code, stack);
        try OpHelpers.vectorLoadLaneZero(u32x4, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_V128_Load64_Zero(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("V128_Load64_Zero", code, stack);
        try OpHelpers.vectorLoadLaneZero(u64x2, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Demote_F64x2_Zero(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Demote_F64x2_Zero", code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        var arr: [4]f32 = undefined;
        arr[0] = @as(f32, @floatCast(vec[0]));
        arr[1] = @as(f32, @floatCast(vec[1]));
        arr[2] = 0.0;
        arr[3] = 0.0;
        const demoted: f32x4 = arr;
        stack.pushV128(@as(v128, @bitCast(demoted)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Promote_Low_F32x4(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Promote_Low_F32x4", code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        var arr: [2]f64 = undefined;
        arr[0] = vec[0];
        arr[1] = vec[1];
        const promoted: f64x2 = arr;
        stack.pushV128(@as(v128, @bitCast(promoted)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Abs", code, stack);
        OpHelpers.vectorAbs(i8x16, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Neg", code, stack);
        const vec = @as(i8x16, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Popcnt(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Popcnt", code, stack);
        const vec = @as(i8x16, @bitCast(stack.popV128()));
        const result: u8x16 = @popCount(vec);
        stack.pushV128(@as(v128, @bitCast(@as(v128, @bitCast(result)))));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_AllTrue(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_AllTrue", code, stack);
        const boolean = OpHelpers.vectorAllTrue(i8x16, stack.popV128());
        stack.pushI32(boolean);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Bitmask(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Bitmask", code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i8x16, stack.popV128());
        stack.pushI32(bitmask);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Narrow_I16x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Narrow_I16x8_S", code, stack);
        OpHelpers.vectorNarrow(i16x8, i8x16, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Narrow_I16x8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Narrow_I16x8_U", code, stack);
        OpHelpers.vectorNarrow(i16x8, u8x16, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Ceil(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Ceil", code, stack);
        OpHelpers.vectorUnOp(f32x4, .Ceil, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Floor(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Floor", code, stack);
        OpHelpers.vectorUnOp(f32x4, .Floor, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Trunc(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Trunc", code, stack);
        OpHelpers.vectorUnOp(f32x4, .Trunc, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Nearest(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Nearest", code, stack);
        OpHelpers.vectorUnOp(f32x4, .Nearest, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Shl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shl", code, stack);
        OpHelpers.vectorShift(i8x16, .Left, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Shr_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shr_S", code, stack);
        OpHelpers.vectorShift(i8x16, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Shr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shr_U", code, stack);
        OpHelpers.vectorShift(u8x16, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Add", code, stack);
        OpHelpers.vectorBinOp(u8x16, .Add, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Add_Sat_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Add_Sat_S", code, stack);
        OpHelpers.vectorBinOp(i8x16, .Add_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Add_Sat_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Add_Sat_U", code, stack);
        OpHelpers.vectorBinOp(u8x16, .Add_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Sub", code, stack);
        OpHelpers.vectorBinOp(u8x16, .Sub, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Sub_Sat_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Sub_Sat_S", code, stack);
        OpHelpers.vectorBinOp(i8x16, .Sub_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Sub_Sat_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Sub_Sat_U", code, stack);
        OpHelpers.vectorBinOp(u8x16, .Sub_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Ceil(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Ceil", code, stack);
        OpHelpers.vectorUnOp(f64x2, .Ceil, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Floor(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Floor", code, stack);
        OpHelpers.vectorUnOp(f64x2, .Floor, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Min_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Min_S", code, stack);
        OpHelpers.vectorBinOp(i8x16, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Min_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Min_U", code, stack);
        OpHelpers.vectorBinOp(u8x16, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Max_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Max_S", code, stack);
        OpHelpers.vectorBinOp(i8x16, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Max_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Max_U", code, stack);
        OpHelpers.vectorBinOp(u8x16, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Trunc(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Trunc", code, stack);
        OpHelpers.vectorUnOp(f64x2, .Trunc, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I8x16_Avgr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I8x16_Avgr_U", code, stack);
        OpHelpers.vectorAvgrU(u8x16, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extadd_Pairwise_I8x16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extadd_Pairwise_I8x16_S", code, stack);
        OpHelpers.vectorAddPairwise(i8x16, i16x8, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extadd_Pairwise_I8x16_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extadd_Pairwise_I8x16_U", code, stack);
        OpHelpers.vectorAddPairwise(u8x16, u16x8, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extadd_Pairwise_I16x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extadd_Pairwise_I16x8_S", code, stack);
        OpHelpers.vectorAddPairwise(i16x8, i32x4, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extadd_Pairwise_I16x8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extadd_Pairwise_I16x8_U", code, stack);
        OpHelpers.vectorAddPairwise(u16x8, u32x4, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Abs", code, stack);
        OpHelpers.vectorAbs(i16x8, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Neg", code, stack);
        const vec = @as(u16x8, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Q15mulr_Sat_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Q15mulr_Sat_S", code, stack);
        const v2 = @as(i16x8, @bitCast(stack.popV128()));
        const v1 = @as(i16x8, @bitCast(stack.popV128()));
        const power: i32 = comptime std.math.powi(i32, 2, 14) catch unreachable;

        var arr: [8]i16 = undefined;
        for (&arr, 0..) |*v, i| {
            const product = @as(i32, v1[i]) * @as(i32, v2[i]) + power;
            const shifted = product >> 15;
            const saturated = std.math.clamp(shifted, std.math.minInt(i16), std.math.maxInt(i16));
            v.* = @as(i16, @intCast(saturated));
        }

        const result: i16x8 = arr;
        stack.pushV128(@as(v128, @bitCast(result)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_AllTrue(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_AllTrue", code, stack);
        const boolean: i32 = OpHelpers.vectorAllTrue(i16x8, stack.popV128());
        stack.pushI32(boolean);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Bitmask(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Bitmask", code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i16x8, stack.popV128());
        stack.pushI32(bitmask);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Narrow_I32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Narrow_I32x4_S", code, stack);
        OpHelpers.vectorNarrow(i32x4, i16x8, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Narrow_I32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Narrow_I32x4_U", code, stack);
        OpHelpers.vectorNarrow(i32x4, u16x8, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extend_Low_I8x16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_Low_I8x16_S", code, stack);
        OpHelpers.vectorExtend(i8x16, i16x8, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extend_High_I8x16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_High_I8x16_S", code, stack);
        OpHelpers.vectorExtend(i8x16, i16x8, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extend_Low_I8x16_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_Low_I8x16_U", code, stack);
        OpHelpers.vectorExtend(u8x16, i16x8, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }
    fn op_I16x8_Extend_High_I8x16_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_High_I8x16_U", code, stack);
        OpHelpers.vectorExtend(u8x16, i16x8, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Shl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Shl", code, stack);
        OpHelpers.vectorShift(i16x8, .Left, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Shr_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Shr_S", code, stack);
        OpHelpers.vectorShift(i16x8, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Shr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Shr_U", code, stack);
        OpHelpers.vectorShift(u16x8, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Add", code, stack);
        OpHelpers.vectorBinOp(i16x8, .Add, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Add_Sat_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Add_Sat_S", code, stack);
        OpHelpers.vectorBinOp(i16x8, .Add_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Add_Sat_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Add_Sat_U", code, stack);
        OpHelpers.vectorBinOp(u16x8, .Add_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Sub", code, stack);
        OpHelpers.vectorBinOp(i16x8, .Sub, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Sub_Sat_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Sub_Sat_S", code, stack);
        OpHelpers.vectorBinOp(i16x8, .Sub_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Sub_Sat_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Sub_Sat_U", code, stack);
        OpHelpers.vectorBinOp(u16x8, .Sub_Sat, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Nearest(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Nearest", code, stack);
        OpHelpers.vectorUnOp(f64x2, .Nearest, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Mul", code, stack);
        OpHelpers.vectorBinOp(i16x8, .Mul, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Min_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Min_S", code, stack);
        OpHelpers.vectorBinOp(i16x8, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Min_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Min_U", code, stack);
        OpHelpers.vectorBinOp(u16x8, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Max_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Max_S", code, stack);
        OpHelpers.vectorBinOp(i16x8, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Max_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Max_U", code, stack);
        OpHelpers.vectorBinOp(u16x8, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Avgr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Avgr_U", code, stack);
        OpHelpers.vectorAvgrU(u16x8, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extmul_Low_I8x16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_Low_I8x16_S", code, stack);
        OpHelpers.vectorMulPairwise(i8x16, i16x8, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extmul_High_I8x16_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_High_I8x16_S", code, stack);
        OpHelpers.vectorMulPairwise(i8x16, i16x8, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extmul_Low_I8x16_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_Low_I8x16_U", code, stack);
        OpHelpers.vectorMulPairwise(u8x16, u16x8, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I16x8_Extmul_High_I8x16_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_High_I8x16_U", code, stack);
        OpHelpers.vectorMulPairwise(u8x16, u16x8, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Abs", code, stack);
        OpHelpers.vectorAbs(i32x4, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Neg", code, stack);
        const vec = @as(i32x4, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_AllTrue(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_AllTrue", code, stack);
        const boolean: i32 = OpHelpers.vectorAllTrue(i32x4, stack.popV128());
        stack.pushI32(boolean);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Bitmask(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Bitmask", code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i32x4, stack.popV128());
        stack.pushI32(bitmask);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extend_Low_I16x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_Low_I16x8_S", code, stack);
        OpHelpers.vectorExtend(i16x8, i32x4, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extend_High_I16x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_High_I16x8_S", code, stack);
        OpHelpers.vectorExtend(i16x8, i32x4, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extend_Low_I16x8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_Low_I16x8_U", code, stack);
        OpHelpers.vectorExtend(u16x8, i32x4, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extend_High_I16x8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_High_I16x8_U", code, stack);
        OpHelpers.vectorExtend(u16x8, i32x4, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Shl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Shl", code, stack);
        OpHelpers.vectorShift(i32x4, .Left, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Shr_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Shr_S", code, stack);
        OpHelpers.vectorShift(i32x4, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Shr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Shr_U", code, stack);
        OpHelpers.vectorShift(u32x4, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Abs", code, stack);
        OpHelpers.vectorAbs(i64x2, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Neg", code, stack);
        const vec = @as(i64x2, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_AllTrue(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_AllTrue", code, stack);
        const boolean = OpHelpers.vectorAllTrue(i64x2, stack.popV128());
        stack.pushI32(boolean);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Bitmask(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Bitmask", code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i64x2, stack.popV128());
        stack.pushI32(bitmask);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Extend_Low_I32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_Low_I32x4_S", code, stack);
        OpHelpers.vectorExtend(i32x4, i64x2, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Extend_High_I32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_High_I32x4_S", code, stack);
        OpHelpers.vectorExtend(i32x4, i64x2, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Extend_Low_I32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_Low_I32x4_U", code, stack);
        OpHelpers.vectorExtend(u32x4, i64x2, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Extend_High_I32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_High_I32x4_U", code, stack);
        OpHelpers.vectorExtend(u32x4, i64x2, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Shl(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Shl", code, stack);
        OpHelpers.vectorShift(i64x2, .Left, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Shr_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Shr_S", code, stack);
        OpHelpers.vectorShift(i64x2, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Shr_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Shr_U", code, stack);
        OpHelpers.vectorShift(u64x2, .Right, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Add", code, stack);
        OpHelpers.vectorBinOp(i32x4, .Add, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Sub", code, stack);
        OpHelpers.vectorBinOp(i32x4, .Sub, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Mul", code, stack);
        OpHelpers.vectorBinOp(i32x4, .Mul, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Min_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Min_S", code, stack);
        OpHelpers.vectorBinOp(i32x4, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Min_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Min_U", code, stack);
        OpHelpers.vectorBinOp(u32x4, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Max_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Max_S", code, stack);
        OpHelpers.vectorBinOp(i32x4, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Max_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Max_U", code, stack);
        OpHelpers.vectorBinOp(u32x4, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Dot_I16x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Dot_I16x8_S", code, stack);
        const i32x8 = @Vector(8, i32);
        const v1: i32x8 = @as(i16x8, @bitCast(stack.popV128()));
        const v2: i32x8 = @as(i16x8, @bitCast(stack.popV128()));
        const product = v1 * v2;
        var arr: [4]i32 = undefined;
        for (&arr, 0..) |*v, i| {
            const p1: i32 = product[i * 2];
            const p2: i32 = product[(i * 2) + 1];
            v.* = p1 +% p2;
        }
        const dot: i32x4 = arr;
        stack.pushV128(@as(v128, @bitCast(dot)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extmul_Low_I16x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_Low_I16x8_S", code, stack);
        OpHelpers.vectorMulPairwise(i16x8, i32x4, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extmul_High_I16x8_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_High_I16x8_S", code, stack);
        OpHelpers.vectorMulPairwise(i16x8, i32x4, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extmul_Low_I16x8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_Low_I16x8_U", code, stack);
        OpHelpers.vectorMulPairwise(u16x8, u32x4, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Extmul_High_I16x8_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_High_I16x8_U", code, stack);
        OpHelpers.vectorMulPairwise(u16x8, u32x4, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Add", code, stack);
        OpHelpers.vectorBinOp(i64x2, .Add, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Sub", code, stack);
        OpHelpers.vectorBinOp(i64x2, .Sub, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_Mul", code, stack);
        OpHelpers.vectorBinOp(i64x2, .Mul, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_EQ(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_EQ", code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Eq, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_NE(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_NE", code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Ne, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_LT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_LT_S", code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Lt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_GT_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_GT_S", code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Gt, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_LE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_LE_S", code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Le, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_GE_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Ge, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I64x2_Extmul_Low_I32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", code, stack);
        OpHelpers.vectorMulPairwise(i32x4, i64x2, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }
    fn op_I64x2_Extmul_High_I32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", code, stack);
        OpHelpers.vectorMulPairwise(i32x4, i64x2, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }
    fn op_I64x2_Extmul_Low_I32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", code, stack);
        OpHelpers.vectorMulPairwise(u32x4, u64x2, .Low, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }
    fn op_I64x2_Extmul_High_I32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", code, stack);
        OpHelpers.vectorMulPairwise(u32x4, u64x2, .High, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Abs", code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        const abs = @abs(vec);
        stack.pushV128(@as(v128, @bitCast(abs)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Neg", code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        const negated = -vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Sqrt(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Sqrt", code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        const root = @sqrt(vec);
        stack.pushV128(@as(v128, @bitCast(root)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Add", code, stack);
        OpHelpers.vectorBinOp(f32x4, .Add, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Sub", code, stack);
        OpHelpers.vectorBinOp(f32x4, .Sub, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Mul", code, stack);
        OpHelpers.vectorBinOp(f32x4, .Mul, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Div(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Div", code, stack);
        OpHelpers.vectorBinOp(f32x4, .Div, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Min(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Min", code, stack);
        OpHelpers.vectorBinOp(f32x4, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Max(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Max", code, stack);
        OpHelpers.vectorBinOp(f32x4, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_PMin(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_PMin", code, stack);
        OpHelpers.vectorBinOp(f32x4, .PMin, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_PMax(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_PMax", code, stack);
        OpHelpers.vectorBinOp(f32x4, .PMax, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Abs(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Abs", code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        const abs = @abs(vec);
        stack.pushV128(@as(v128, @bitCast(abs)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Neg(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Neg", code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        const negated = -vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Sqrt(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Sqrt", code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        const root = @sqrt(vec);
        stack.pushV128(@as(v128, @bitCast(root)));
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Add(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Add", code, stack);
        OpHelpers.vectorBinOp(f64x2, .Add, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Sub(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Sub", code, stack);
        OpHelpers.vectorBinOp(f64x2, .Sub, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Mul(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Mul", code, stack);
        OpHelpers.vectorBinOp(f64x2, .Mul, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Div(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Div", code, stack);
        OpHelpers.vectorBinOp(f64x2, .Div, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Min(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Min", code, stack);
        OpHelpers.vectorBinOp(f64x2, .Min, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Max(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Max", code, stack);
        OpHelpers.vectorBinOp(f64x2, .Max, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_PMin(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_PMin", code, stack);
        OpHelpers.vectorBinOp(f64x2, .PMin, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_PMax(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_PMax", code, stack);
        OpHelpers.vectorBinOp(f64x2, .PMax, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Trunc_Sat_F32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Trunc_Sat_F32x4_S", code, stack);
        OpHelpers.vectorConvert(f32x4, i32x4, .Low, .Saturate, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Trunc_Sat_F32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Trunc_Sat_F32x4_U", code, stack);
        OpHelpers.vectorConvert(f32x4, u32x4, .Low, .Saturate, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Convert_I32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Convert_I32x4_S", code, stack);
        OpHelpers.vectorConvert(i32x4, f32x4, .Low, .SafeCast, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F32x4_Convert_I32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F32x4_Convert_I32x4_U", code, stack);
        OpHelpers.vectorConvert(u32x4, f32x4, .Low, .SafeCast, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Trunc_Sat_F64x2_S_Zero(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Trunc_Sat_F64x2_S_Zero", code, stack);
        OpHelpers.vectorConvert(f64x2, i32x4, .Low, .Saturate, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_I32x4_Trunc_Sat_F64x2_U_Zero(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("I32x4_Trunc_Sat_F64x2_U_Zero", code, stack);
        OpHelpers.vectorConvert(f64x2, u32x4, .Low, .Saturate, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Convert_Low_I32x4_S(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Convert_Low_I32x4_S", code, stack);
        OpHelpers.vectorConvert(i32x4, f64x2, .Low, .SafeCast, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }

    fn op_F64x2_Convert_Low_I32x4_U(code: *InstructionStreamReader, stack: *Stack) anyerror!void {
        try preamble("F64x2_Convert_Low_I32x4_U", code, stack);
        OpHelpers.vectorConvert(u32x4, f64x2, .Low, .SafeCast, stack);
        code.advance(void);
        try @call(.always_tail, InstructionFuncs.lookup(code.opcode()), .{ code, stack });
    }
};

pub const StackVM = struct {
    const TrapType = enum {
        Step,
        Explicit,
    };

    const TrappedOpcode = struct {
        address: u32,
        opcode: Opcode,
        type: TrapType,
    };

    const DebugState = struct {
        trapped_opcodes: std.ArrayList(TrappedOpcode), // TODO multiarraylist?
        module_instance: *ModuleInstance,
        pc: usize = 0,
        trap_counter: u32 = 0, // used for trapping on step
        is_invoking: bool = false,

        fn onInvokeFinished(state: *DebugState) void {
            state.pc = 0;
            state.is_invoking = false;
            state.trap_counter = 0;
        }
    };

    const MeterState = if (metering.enabled) struct {
        pc: usize = 0,
        opcode: Opcode = Opcode.Invalid,
        meter: metering.Meter,
        enabled: bool = false,

        fn onInvokeFinished(state: *MeterState) void {
            state.pc = 0;
        }
    } else void;

    stack: Stack,
    functions: std.ArrayList(FunctionInstance),
    instructions: InstructionStream,
    instructions_reader: InstructionStreamReader,
    debug_state: ?DebugState,
    meter_state: MeterState,

    new_to_old_continuation: std.AutoHashMap(usize, u32),

    fn fromVM(vm: *VM) *StackVM {
        return @as(*StackVM, @alignCast(@ptrCast(vm.impl)));
    }

    pub fn init(vm: *VM) void {
        var self: *StackVM = fromVM(vm);
        self.stack = Stack.init(vm.allocator);
        self.functions = std.ArrayList(FunctionInstance).init(vm.allocator);
        self.instructions = InstructionStream.init(vm.allocator);
        self.instructions_reader = self.instructions.reader(0);
        self.new_to_old_continuation = std.AutoHashMap(usize, u32).init(vm.allocator);
        self.debug_state = null;
    }

    pub fn deinit(vm: *VM) void {
        var self: *StackVM = fromVM(vm);

        for (self.functions.items) |*func| {
            func.deinit();
        }

        self.functions.deinit();
        self.instructions.deinit();

        self.stack.deinit();
        if (self.debug_state) |*debug_state| {
            debug_state.trapped_opcodes.deinit();
        }

        self.new_to_old_continuation.deinit();
    }

    pub fn instantiate(vm: *VM, module: *ModuleInstance, opts: ModuleInstantiateOpts) anyerror!void {
        var self: *StackVM = fromVM(vm);

        if (opts.enable_debug) { // TODO move this to compile-time flag
            self.debug_state = DebugState{
                .module_instance = module,
                .pc = 0,
                .trapped_opcodes = std.ArrayList(TrappedOpcode).init(vm.allocator),
            };
        }

        const stack_size = if (opts.stack_size > 0) opts.stack_size else 1024 * 128;
        const stack_size_f = @as(f64, @floatFromInt(stack_size));

        try self.stack.allocMemory(.{
            .max_values = @as(u32, @intFromFloat(stack_size_f * 0.85)),
            .max_labels = @as(u16, @intFromFloat(stack_size_f * 0.14)),
            .max_frames = @as(u16, @intFromFloat(stack_size_f * 0.01)),
        });

        // transform instruction structs to compact instruction stream
        var old_to_new_continuation = try std.ArrayList(u32).initCapacity(vm.allocator, module.module_def.code.instructions.items.len);
        var continuations_to_fixup_offset = std.ArrayList(usize).init(vm.allocator);

        for (module.module_def.code.instructions.items) |instruction| {
            const old_continuation: u32 = @intCast(old_to_new_continuation.items.len);
            const new_continuation: u32 = self.instructions.length();
            std.debug.assert(new_continuation == std.mem.alignForward(u32, new_continuation, @alignOf(Opcode)));
            old_to_new_continuation.appendAssumeCapacity(new_continuation);

            try self.new_to_old_continuation.put(new_continuation, old_continuation);
            try self.instructions.emit(instruction.opcode, instruction.immediate, null, &continuations_to_fixup_offset);
        }

        for (continuations_to_fixup_offset.items) |fixup_offset| {
            const fixup_ptr: [*]u8 = self.instructions.data.items.ptr + fixup_offset;
            const fixup: *u32 = @ptrCast(@alignCast(fixup_ptr));
            const old_continuation: u32 = fixup.*;
            const new_continuation: u32 = old_to_new_continuation.items[old_continuation];
            fixup.* = new_continuation;
        }

        // instantiate functions
        try self.functions.ensureTotalCapacity(module.module_def.functions.items.len);
        for (module.module_def.functions.items, 0..) |*def_func, i| {
            const func_type: *const FunctionTypeDefinition = &module.module_def.types.items[def_func.type_index];
            const param_types: []const ValType = func_type.getParams();

            var local_types = std.ArrayList(ValType).init(vm.allocator);
            try local_types.ensureTotalCapacity(param_types.len + def_func.locals.items.len);
            local_types.appendSliceAssumeCapacity(param_types);
            local_types.appendSliceAssumeCapacity(def_func.locals.items);

            const f = FunctionInstance{
                .type_def_index = def_func.type_index,
                .def_index = @as(u32, @intCast(i)),
                .instructions_begin = old_to_new_continuation.items[def_func.instructions_begin],
                .local_types = local_types,
            };
            try self.functions.append(f);
        }

        self.instructions_reader = self.instructions.reader(0); // reinitialize now that self.instructions has data
    }

    pub fn invoke(vm: *VM, module: *ModuleInstance, handle: FunctionHandle, params: [*]const Val, returns: [*]Val, opts: InvokeOpts) anyerror!void {
        var self: *StackVM = fromVM(vm);

        if (self.debug_state) |*debug_state| {
            debug_state.pc = 0;
            debug_state.is_invoking = true;

            if (opts.trap_on_start) {
                debug_state.trap_counter = 1;
            }
        }
        if (metering.enabled) {
            if (opts.meter != metering.initial_meter) {
                self.meter_state = .{
                    .enabled = true,
                    .meter = opts.meter,
                    .opcode = Opcode.Invalid,
                };
            }
        }

        switch (handle.type) {
            .Export => try self.invokeInternal(module, handle.index, params, returns),
            .Import => try invokeImportInternal(module, handle.index, params, returns, opts),
        }
    }

    pub fn invokeWithIndex(vm: *VM, module: *ModuleInstance, func_index: usize, params: [*]const Val, returns: [*]Val) anyerror!void {
        var self: *StackVM = fromVM(vm);

        const num_imports = module.module_def.imports.functions.items.len;
        if (func_index >= num_imports) {
            const instance_index = func_index - num_imports;
            try self.invokeInternal(module, instance_index, params, returns);
        } else {
            try invokeImportInternal(module, func_index, params, returns, .{});
        }
    }

    pub fn resumeInvoke(vm: *VM, module: *ModuleInstance, returns: []Val, opts: ResumeInvokeOpts) anyerror!void {
        var self: *StackVM = fromVM(vm);

        var pc: usize = 0;
        var opcode = Opcode.Invalid;
        if (self.debug_state) |debug_state| {
            std.debug.assert(debug_state.is_invoking);
            pc = debug_state.pc;
            for (debug_state.trapped_opcodes.items) |op| {
                if (op.address == debug_state.pc) {
                    opcode = op.opcode;
                    break;
                }
            }
            unreachable; // Should never get into a state where a trapped opcode doesn't have an associated record

        } else if (metering.enabled) {
            std.debug.assert(self.meter_state.enabled);
            pc = self.meter_state.pc;
            if (opts.meter != metering.initial_meter) {
                self.meter_state.meter = opts.meter;
            }
            opcode = self.meter_state.opcode;
        } else {
            // There was no debug or meter information, so nothing to resume.
            return error.TrapInvalidResume;
        }

        const op_func = InstructionFuncs.lookup(opcode);
        try op_func(pc, module.module_def.code.instructions.items.ptr, &self.stack);

        if (returns.len > 0) {
            var index: i32 = @as(i32, @intCast(returns.len - 1));
            while (index >= 0) {
                returns[@as(usize, @intCast(index))] = self.stack.popValue();
                index -= 1;
            }
        }

        if (self.debug_state) |*debug_state| {
            debug_state.onInvokeFinished();
        }
        if (metering.enabled) {
            self.meter_state.onInvokeFinished();
        }
    }

    pub fn step(vm: *VM, module: *ModuleInstance, returns: []Val) !void {
        var self: *StackVM = fromVM(vm);

        const debug_state = &self.debug_state.?;

        if (debug_state.is_invoking == false) {
            return;
        }

        // Don't trap on the first instruction executed, but the next. Note that we can't just trap pc + 1
        // since the current instruction may branch.
        debug_state.trap_counter = 2;

        try vm.resumeInvoke(module, returns, .{});
    }

    pub fn setDebugTrap(vm: *VM, module: *ModuleInstance, wasm_address: u32, mode: DebugTrapInstructionMode) !bool {
        var self: *StackVM = fromVM(vm);

        std.debug.assert(self.debug_state != null);
        const instruction_index = module.module_def.code.wasm_address_to_instruction_index.get(wasm_address) orelse return false;

        var debug_state = &self.debug_state.?;
        for (debug_state.trapped_opcodes.items, 0..) |*existing, i| {
            if (existing.address == instruction_index and (existing.type == .Step or existing.type == .Explicit)) {
                switch (mode) {
                    .Enable => {},
                    .Disable => {
                        _ = debug_state.trapped_opcodes.swapRemove(i);
                    },
                }
                return true;
            }
        }

        if (mode == .Enable) {
            var instructions: []Instruction = module.module_def.code.instructions.items;
            const original_op = instructions[instruction_index].opcode;
            instructions[instruction_index].opcode = .DebugTrap;

            try debug_state.trapped_opcodes.append(TrappedOpcode{
                .opcode = original_op,
                .address = instruction_index,
                .type = .Explicit,
            });
            return true;
        }

        return false;
    }

    pub fn formatBacktrace(vm: *VM, indent: u8, allocator: std.mem.Allocator) anyerror!std.ArrayList(u8) {
        var self: *StackVM = fromVM(vm);

        var buffer = std.ArrayList(u8).init(allocator);
        try buffer.ensureTotalCapacity(512);
        var writer = buffer.writer();

        for (self.stack.frames[0..self.stack.num_frames], 0..) |_, i| {
            const reverse_index = (self.stack.num_frames - 1) - i;
            const frame: *const CallFrame = &self.stack.frames[reverse_index];

            var indent_level: usize = 0;
            while (indent_level < indent) : (indent_level += 1) {
                try writer.print("\t", .{});
            }

            const name_section: *const NameCustomSection = &frame.module_instance.module_def.name_section;
            const module_name = name_section.getModuleName();

            const func_name_index: usize = frame.func.def_index + frame.module_instance.module_def.imports.functions.items.len;
            const function_name = name_section.findFunctionName(func_name_index);

            try writer.print("{}: {s}!{s}\n", .{ reverse_index, module_name, function_name });
        }

        return buffer;
    }

    pub fn findFuncTypeDef(vm: *VM, module: *ModuleInstance, local_func_index: usize) *const FunctionTypeDefinition {
        var self: *StackVM = fromVM(vm);

        const func_instance: *const FunctionInstance = &self.functions.items[local_func_index];
        const func_type_def: *const FunctionTypeDefinition = &module.module_def.types.items[func_instance.type_def_index];
        return func_type_def;
    }

    fn invokeInternal(self: *StackVM, module: *ModuleInstance, func_instance_index: usize, params: [*]const Val, returns: [*]Val) !void {
        const func: FunctionInstance = self.functions.items[func_instance_index];
        const func_def: FunctionDefinition = module.module_def.functions.items[func.def_index];
        const func_type: *const FunctionTypeDefinition = &module.module_def.types.items[func.type_def_index];
        const param_types: []const ValType = func_type.getParams();
        const return_types: []const ValType = func_type.getReturns();

        const params_slice = params[0..param_types.len];
        var returns_slice = returns[0..return_types.len];

        // Ensure any leftover stack state doesn't pollute this invoke. Can happen if the previous invoke returned an error.
        self.stack.popAll();

        // pushFrame() assumes the stack already contains the params to the function, so ensure they exist
        // on the value stack
        for (params_slice) |v| {
            self.stack.pushValue(v);
        }

        try self.stack.pushFrame(&func, module, param_types, func.local_types.items, func_type.calcNumReturns());
        try self.stack.pushLabel(.Invalid, @as(u32, @intCast(return_types.len)), @intCast(func_def.continuation));

        DebugTrace.traceFunction(module, self.stack.num_frames, func.def_index);

        self.instructions_reader = self.instructions.reader(func.instructions_begin);

        try InstructionFuncs.run(&self.instructions_reader, &self.stack);

        if (returns_slice.len > 0) {
            var index: i32 = @as(i32, @intCast(returns_slice.len - 1));
            while (index >= 0) {
                returns_slice[@as(usize, @intCast(index))] = self.stack.popValue();
                index -= 1;
            }
        }

        if (self.debug_state) |*debug_state| {
            debug_state.onInvokeFinished();
        }

        if (metering.enabled and self.meter_state.enabled) {
            self.meter_state.onInvokeFinished();
        }
    }

    fn invokeImportInternal(module: *ModuleInstance, import_index: usize, params: [*]const Val, returns: [*]Val, opts: InvokeOpts) !void {
        const func_import: *const FunctionImport = &module.store.imports.functions.items[import_index];
        switch (func_import.data) {
            .Host => |data| {
                DebugTrace.traceHostFunction(module, 1, func_import.name);

                data.callback(data.userdata, module, params, returns);
            },
            .Wasm => |data| {
                var import_instance: *ModuleInstance = data.module_instance;
                const handle: FunctionHandle = try import_instance.getFunctionHandle(func_import.name); // TODO could cache this in the func_import
                try import_instance.vm.invoke(import_instance, handle, params, returns, opts);
            },
        }
    }
};
