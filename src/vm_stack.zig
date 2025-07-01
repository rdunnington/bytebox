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

const shared = @import("stack.zig");
const FunctionInstance = shared.FunctionInstance;
const CallFrame = shared.CallFrame;
const FuncCallData = shared.FuncCallData;
const Label = shared.Label;
const Stack = shared.Stack;
const OpHelpers = shared.OpHelpers;

// TODO move all definition stuff into definition.zig and vm stuff into vm_stack.zig

// pc is the "program counter", which points to the next instruction to execute
const InstructionFunc = *const fn (pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void;

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
        &op_Call_Local,
        &op_Call_Import,
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

    fn run(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try @call(.always_tail, InstructionFuncs.lookup(code[pc].opcode), .{ pc, code, stack });
    }

    fn lookup(opcode: Opcode) InstructionFunc {
        return opcodeToFuncTable[@intFromEnum(opcode)];
    }

    inline fn preamble(name: []const u8, pc: u32, code: [*]const Instruction, stack: *Stack) !void {
        return shared.preamble(StackVM, name, pc, code, stack);
    }

    fn op_Invalid(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Invalid", pc, code, stack);
        unreachable;
    }

    fn op_Unreachable(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Unreachable", pc, code, stack);
        return error.TrapUnreachable;
    }

    fn op_DebugTrap(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("DebugTrap", pc, code, stack);
        const root_module_instance: *ModuleInstance = stack.frames[0].module_instance;
        const stack_vm = StackVM.fromVM(root_module_instance.vm);

        std.debug.assert(stack_vm.debug_state != null);
        stack_vm.debug_state.?.pc = pc;

        return error.TrapDebug;
    }

    fn op_Noop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Noop", pc, code, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Block(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Block", pc, code, stack);
        stack.pushLabel(code[pc].immediate.Block.num_returns, code[pc].immediate.Block.continuation);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Loop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Loop", pc, code, stack);
        stack.pushLabel(code[pc].immediate.Block.num_returns, code[pc].immediate.Block.continuation);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_If(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("If", pc, code, stack);
        const next_pc = try OpHelpers.ifCond(stack, pc, code);

        try @call(.always_tail, InstructionFuncs.lookup(code[next_pc].opcode), .{ next_pc, code, stack });
    }

    fn op_IfNoElse(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("IfNoElse", pc, code, stack);
        const next_pc = try OpHelpers.ifNoElse(stack, pc, code);

        try @call(.always_tail, InstructionFuncs.lookup(code[next_pc].opcode), .{ next_pc, code, stack });
    }

    fn op_Else(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Else", pc, code, stack);
        // getting here means we reached the end of the if opcode chain, so skip to the true end opcode
        const next_pc: u32 = code[pc].immediate.If.end_continuation;
        try @call(.always_tail, InstructionFuncs.lookup(code[next_pc].opcode), .{ next_pc, code, stack });
    }

    fn op_End(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("End", pc, code, stack);
        const next = OpHelpers.end(stack, pc, code) orelse return;
        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Branch(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Branch", pc, code, stack);
        const label_id: u32 = code[pc].immediate.LabelId;
        const next: FuncCallData = OpHelpers.branch(stack, label_id) orelse return;
        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Branch_If(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Branch_If", pc, code, stack);
        const next = OpHelpers.branchIf(stack, pc, code) orelse return;
        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Branch_Table(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Branch_Table", pc, code, stack);

        const next = OpHelpers.branchTable(stack, code[pc]) orelse return;

        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Return(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Return", pc, code, stack);
        const next: FuncCallData = stack.popFrame() orelse return;
        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Call_Local(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Call", pc, code, stack);
        const next: FuncCallData = try OpHelpers.callLocal(StackVM, stack, pc, code);

        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Call_Import(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Call", pc, code, stack);

        const next = try OpHelpers.callImport(StackVM, stack, pc, code);

        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Call_Indirect(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Call_Indirect", pc, code, stack);

        const next = try OpHelpers.callIndirect(StackVM, stack, pc, code);

        try @call(.always_tail, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Drop", pc, code, stack);
        _ = stack.popValue();
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Select(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Select", pc, code, stack);

        const boolean: i32 = stack.popI32();
        const v2: Val = stack.popValue();
        const v1: Val = stack.popValue();

        if (boolean != 0) {
            stack.pushValue(v1);
        } else {
            stack.pushValue(v2);
        }

        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Select_T(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Select_T", pc, code, stack);

        const boolean: i32 = stack.popI32();
        const v2: Val = stack.popValue();
        const v1: Val = stack.popValue();

        if (boolean != 0) {
            stack.pushValue(v1);
        } else {
            stack.pushValue(v2);
        }

        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Local_Get(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Local_Get", pc, code, stack);
        const locals_index: u32 = code[pc].immediate.Index;
        const frame: *const CallFrame = stack.topFrame();
        const v: Val = frame.locals[locals_index];
        stack.pushValue(v);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Local_Set(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Local_Set", pc, code, stack);

        const locals_index: u32 = code[pc].immediate.Index;
        var frame: *CallFrame = stack.topFrame();
        const v: Val = stack.popValue();
        frame.locals[locals_index] = v;
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Local_Tee(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Local_Tee", pc, code, stack);
        const locals_index: u32 = code[pc].immediate.Index;
        var frame: *CallFrame = stack.topFrame();
        const v: Val = stack.topValue();
        frame.locals[locals_index] = v;
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Global_Get(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Global_Get", pc, code, stack);
        const global_index: u32 = code[pc].immediate.Index;
        const global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        stack.pushValue(global.value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Global_Set(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Global_Set", pc, code, stack);
        const global_index: u32 = code[pc].immediate.Index;
        const global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        global.value = stack.popValue();
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Get(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Table_Get", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        const table: *const TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const index: i32 = stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        const ref = table.refs.items[@as(usize, @intCast(index))];
        stack.pushValue(ref);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Set(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Table_Set", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        var table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const ref = stack.popValue();
        const index: i32 = stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        table.refs.items[@as(usize, @intCast(index))] = ref;
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Load", pc, code, stack);
        const value = try OpHelpers.loadFromMem(i32, stack, code[pc].immediate.MemoryOffset);
        stack.pushI32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Load", pc, code, stack);
        const value = try OpHelpers.loadFromMem(i64, stack, code[pc].immediate.MemoryOffset);
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Load", pc, code, stack);
        const value = try OpHelpers.loadFromMem(f32, stack, code[pc].immediate.MemoryOffset);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Load", pc, code, stack);
        const value = try OpHelpers.loadFromMem(f64, stack, code[pc].immediate.MemoryOffset);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Load8_S", pc, code, stack);
        const value: i32 = try OpHelpers.loadFromMem(i8, stack, code[pc].immediate.MemoryOffset);
        stack.pushI32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Load8_U", pc, code, stack);
        const value: u32 = try OpHelpers.loadFromMem(u8, stack, code[pc].immediate.MemoryOffset);
        stack.pushI32(@as(i32, @bitCast(value)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Load16_S", pc, code, stack);
        const value: i32 = try OpHelpers.loadFromMem(i16, stack, code[pc].immediate.MemoryOffset);
        stack.pushI32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Load16_U", pc, code, stack);
        const value: u32 = try OpHelpers.loadFromMem(u16, stack, code[pc].immediate.MemoryOffset);
        stack.pushI32(@as(i32, @bitCast(value)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Load8_S", pc, code, stack);
        const value: i64 = try OpHelpers.loadFromMem(i8, stack, code[pc].immediate.MemoryOffset);
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Load8_U", pc, code, stack);
        const value: u64 = try OpHelpers.loadFromMem(u8, stack, code[pc].immediate.MemoryOffset);
        stack.pushI64(@as(i64, @bitCast(value)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Load16_S", pc, code, stack);
        const value: i64 = try OpHelpers.loadFromMem(i16, stack, code[pc].immediate.MemoryOffset);
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Load16_U", pc, code, stack);
        const value: u64 = try OpHelpers.loadFromMem(u16, stack, code[pc].immediate.MemoryOffset);
        stack.pushI64(@as(i64, @bitCast(value)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Load32_S", pc, code, stack);
        const value: i64 = try OpHelpers.loadFromMem(i32, stack, code[pc].immediate.MemoryOffset);
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Load32_U", pc, code, stack);
        const value: u64 = try OpHelpers.loadFromMem(u32, stack, code[pc].immediate.MemoryOffset);
        stack.pushI64(@as(i64, @bitCast(value)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Store", pc, code, stack);
        const value: i32 = stack.popI32();
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Store", pc, code, stack);
        const value: i64 = stack.popI64();
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Store", pc, code, stack);
        const value: f32 = stack.popF32();
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Store", pc, code, stack);
        const value: f64 = stack.popF64();
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Store8(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Store8", pc, code, stack);
        const value: i8 = @as(i8, @truncate(stack.popI32()));
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Store16(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Store16", pc, code, stack);
        const value: i16 = @as(i16, @truncate(stack.popI32()));
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store8(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Store8", pc, code, stack);
        const value: i8 = @as(i8, @truncate(stack.popI64()));
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store16(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Store16", pc, code, stack);
        const value: i16 = @as(i16, @truncate(stack.popI64()));
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Store32", pc, code, stack);
        const value: i32 = @as(i32, @truncate(stack.popI64()));
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Size(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Memory_Size", pc, code, stack);
        const memory_index: usize = 0;
        var memory_instance: *const MemoryInstance = stack.topFrame().module_instance.store.getMemory(memory_index);

        switch (memory_instance.limits.indexType()) {
            .I32 => stack.pushI32(@intCast(memory_instance.size())),
            .I64 => stack.pushI64(@intCast(memory_instance.size())),
            else => unreachable,
        }

        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Grow(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Memory_Grow", pc, code, stack);
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
            try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
        } else {
            switch (memory_instance.limits.indexType()) {
                .I32 => stack.pushI32(-1),
                .I64 => stack.pushI64(-1),
                else => unreachable,
            }
            try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
        }
    }

    fn op_I32_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Const", pc, code, stack);
        const v: i32 = code[pc].immediate.ValueI32;
        stack.pushI32(v);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Const", pc, code, stack);
        const v: i64 = code[pc].immediate.ValueI64;
        stack.pushI64(v);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Const", pc, code, stack);
        const v: f32 = code[pc].immediate.ValueF32;
        stack.pushF32(v);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Const", pc, code, stack);
        OpHelpers.f64Const(stack, code[pc]);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Eqz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Eqz", pc, code, stack);
        OpHelpers.i32Eqz(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Eq(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Eq", pc, code, stack);
        OpHelpers.i32Eq(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_NE", pc, code, stack);
        OpHelpers.i32Ne(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_LT_S", pc, code, stack);
        OpHelpers.i32LtS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_LT_U", pc, code, stack);
        OpHelpers.i32LtU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_GT_S", pc, code, stack);
        OpHelpers.i32GtS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_GT_U", pc, code, stack);
        OpHelpers.i32GtU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_LE_S", pc, code, stack);
        OpHelpers.i32LeS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_LE_U", pc, code, stack);
        OpHelpers.i32LeU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_GE_S", pc, code, stack);
        OpHelpers.i32GeS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_GE_U", pc, code, stack);
        OpHelpers.i32GeU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Eqz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Eqz", pc, code, stack);
        OpHelpers.i64Eqz(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Eq(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Eq", pc, code, stack);
        OpHelpers.i64Eq(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_NE", pc, code, stack);
        OpHelpers.i64Ne(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_LT_S", pc, code, stack);
        OpHelpers.i64LtS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_LT_U", pc, code, stack);
        OpHelpers.i64LtU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_GT_S", pc, code, stack);
        OpHelpers.i64GtS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_GT_U", pc, code, stack);
        OpHelpers.i64GtU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_LE_S", pc, code, stack);
        OpHelpers.i64LeS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_LE_U", pc, code, stack);
        OpHelpers.i64LeU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_GE_S", pc, code, stack);
        OpHelpers.i64GeS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_GE_U", pc, code, stack);
        OpHelpers.i64GeU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_EQ", pc, code, stack);
        OpHelpers.f32Eq(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_NE", pc, code, stack);
        OpHelpers.f32Ne(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_LT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_LT", pc, code, stack);
        OpHelpers.f32Lt(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_GT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_GT", pc, code, stack);
        OpHelpers.f32Gt(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_LE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_LE", pc, code, stack);
        OpHelpers.f32Le(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_GE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_GE", pc, code, stack);
        OpHelpers.f32Ge(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_EQ", pc, code, stack);
        OpHelpers.f64Eq(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_NE", pc, code, stack);
        OpHelpers.f64Ne(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_LT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_LT", pc, code, stack);
        OpHelpers.f64Lt(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_GT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_GT", pc, code, stack);
        OpHelpers.f64Gt(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_LE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_LE", pc, code, stack);
        OpHelpers.f64Le(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_GE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_GE", pc, code, stack);
        OpHelpers.f64Ge(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Clz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Clz", pc, code, stack);
        OpHelpers.i32Clz(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Ctz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Ctz", pc, code, stack);
        OpHelpers.i32Ctz(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Popcnt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Popcnt", pc, code, stack);
        OpHelpers.i32Popcnt(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Add", pc, code, stack);
        OpHelpers.i32Add(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Sub", pc, code, stack);
        OpHelpers.i32Sub(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Mul", pc, code, stack);
        OpHelpers.i32Mul(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Div_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Div_S", pc, code, stack);
        try OpHelpers.i32DivS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Div_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Div_U", pc, code, stack);
        try OpHelpers.i32DivU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rem_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Rem_S", pc, code, stack);
        try OpHelpers.i32RemS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rem_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Rem_U", pc, code, stack);
        try OpHelpers.i32RemU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_And(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_And", pc, code, stack);
        OpHelpers.i32And(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Or(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Or", pc, code, stack);
        OpHelpers.i32Or(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Xor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Xor", pc, code, stack);
        OpHelpers.i32Xor(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Shl", pc, code, stack);
        try OpHelpers.i32Shl(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Shr_S", pc, code, stack);
        try OpHelpers.i32ShrS(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Shr_U", pc, code, stack);
        try OpHelpers.i32ShrU(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rotl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Rotl", pc, code, stack);
        OpHelpers.i32Rotl(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rotr(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Rotr", pc, code, stack);
        OpHelpers.i32Rotr(stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Clz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Clz", pc, code, stack);
        const v: i64 = stack.popI64();
        const num_zeroes = @clz(v);
        stack.pushI64(num_zeroes);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Ctz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Ctz", pc, code, stack);
        const v: i64 = stack.popI64();
        const num_zeroes = @ctz(v);
        stack.pushI64(num_zeroes);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Popcnt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Popcnt", pc, code, stack);
        const v: i64 = stack.popI64();
        const num_bits_set = @popCount(v);
        stack.pushI64(num_bits_set);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Add", pc, code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result = v1 +% v2;
        stack.pushI64(result);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Sub", pc, code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const result = v1 -% v2;
        stack.pushI64(result);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Mul", pc, code, stack);
        const v2: i64 = stack.popI64();
        const v1: i64 = stack.popI64();
        const value = v1 *% v2;
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Div_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Div_S", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Div_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Div_U", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rem_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Rem_S", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rem_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Rem_U", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_And(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_And", pc, code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(v1 & v2));
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Or(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Or", pc, code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(v1 | v2));
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Xor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Xor", pc, code, stack);
        const v2: u64 = @as(u64, @bitCast(stack.popI64()));
        const v1: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(v1 ^ v2));
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Shl", pc, code, stack);
        const shift_unsafe: i64 = stack.popI64();
        const int: i64 = stack.popI64();
        const shift: i64 = try std.math.mod(i64, shift_unsafe, 64);
        const value = std.math.shl(i64, int, shift);
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Shr_S", pc, code, stack);
        const shift_unsafe: i64 = stack.popI64();
        const int: i64 = stack.popI64();
        const shift = try std.math.mod(i64, shift_unsafe, 64);
        const value = std.math.shr(i64, int, shift);
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Shr_U", pc, code, stack);
        const shift_unsafe: u64 = @as(u64, @bitCast(stack.popI64()));
        const int: u64 = @as(u64, @bitCast(stack.popI64()));
        const shift = try std.math.mod(u64, shift_unsafe, 64);
        const value = @as(i64, @bitCast(std.math.shr(u64, int, shift)));
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rotl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Rotl", pc, code, stack);
        const rot: u64 = @as(u64, @bitCast(stack.popI64()));
        const int: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(std.math.rotl(u64, int, rot)));
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rotr(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Rotr", pc, code, stack);
        const rot: u64 = @as(u64, @bitCast(stack.popI64()));
        const int: u64 = @as(u64, @bitCast(stack.popI64()));
        const value = @as(i64, @bitCast(std.math.rotr(u64, int, rot)));
        stack.pushI64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Abs", pc, code, stack);
        const f = stack.popF32();
        const value = @abs(f);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Neg", pc, code, stack);
        const f = stack.popF32();
        stack.pushF32(-f);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Ceil(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Ceil", pc, code, stack);
        const f = stack.popF32();
        const value = @ceil(f);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Floor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Floor", pc, code, stack);
        const f = stack.popF32();
        const value = @floor(f);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Trunc(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Trunc", pc, code, stack);
        const f = stack.popF32();
        const value = std.math.trunc(f);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Nearest(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Nearest", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Sqrt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Sqrt", pc, code, stack);
        const f = stack.popF32();
        const value = std.math.sqrt(f);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Add", pc, code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 + v2;
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Sub", pc, code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 - v2;
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Mul", pc, code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 * v2;
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Div", pc, code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = v1 / v2;
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Min(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Min", pc, code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = OpHelpers.propagateNanWithOp(.Min, v1, v2);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Max(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Max", pc, code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = OpHelpers.propagateNanWithOp(.Max, v1, v2);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Copysign(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Copysign", pc, code, stack);
        const v2 = stack.popF32();
        const v1 = stack.popF32();
        const value = std.math.copysign(v1, v2);
        stack.pushF32(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Abs", pc, code, stack);
        const f = stack.popF64();
        const value = @abs(f);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Neg", pc, code, stack);
        const f = stack.popF64();
        stack.pushF64(-f);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Ceil(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Ceil", pc, code, stack);
        const f = stack.popF64();
        const value = @ceil(f);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Floor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Floor", pc, code, stack);
        const f = stack.popF64();
        const value = @floor(f);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Trunc(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Trunc", pc, code, stack);
        const f = stack.popF64();
        const value = @trunc(f);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Nearest(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Nearest", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Sqrt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Sqrt", pc, code, stack);
        const f = stack.popF64();
        const value = std.math.sqrt(f);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Add", pc, code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 + v2;
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Sub", pc, code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 - v2;
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Mul", pc, code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 * v2;
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Div", pc, code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = v1 / v2;
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Min(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Min", pc, code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = OpHelpers.propagateNanWithOp(.Min, v1, v2);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Max(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Max", pc, code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = OpHelpers.propagateNanWithOp(.Max, v1, v2);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Copysign(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Copysign", pc, code, stack);
        const v2 = stack.popF64();
        const v1 = stack.popF64();
        const value = std.math.copysign(v1, v2);
        stack.pushF64(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Wrap_I64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Wrap_I64", pc, code, stack);
        const v = stack.popI64();
        const mod = @as(i32, @truncate(v));
        stack.pushI32(mod);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F32_S", pc, code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(i32, v);
        stack.pushI32(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F32_U", pc, code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F64_S", pc, code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(i32, v);
        stack.pushI32(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_F64_U", pc, code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend_I32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Extend_I32_S", pc, code, stack);
        const v32 = stack.popI32();
        const v64: i64 = v32;
        stack.pushI64(v64);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend_I32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Extend_I32_U", pc, code, stack);
        const v32 = stack.popI32();
        const v64: u64 = @as(u32, @bitCast(v32));
        stack.pushI64(@as(i64, @bitCast(v64)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F32_S", pc, code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(i64, v);
        stack.pushI64(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F32_U", pc, code, stack);
        const v = stack.popF32();
        const int = try OpHelpers.truncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F64_S", pc, code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(i64, v);
        stack.pushI64(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_F64_U", pc, code, stack);
        const v = stack.popF64();
        const int = try OpHelpers.truncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I32_S", pc, code, stack);
        const v = stack.popI32();
        stack.pushF32(@as(f32, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I32_U", pc, code, stack);
        const v = @as(u32, @bitCast(stack.popI32()));
        stack.pushF32(@as(f32, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I64_S", pc, code, stack);
        const v = stack.popI64();
        stack.pushF32(@as(f32, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Convert_I64_U", pc, code, stack);
        const v = @as(u64, @bitCast(stack.popI64()));
        stack.pushF32(@as(f32, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Demote_F64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Demote_F64", pc, code, stack);
        const v = stack.popF64();
        stack.pushF32(@as(f32, @floatCast(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I32_S", pc, code, stack);
        const v = stack.popI32();
        stack.pushF64(@as(f64, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I32_U", pc, code, stack);
        const v = @as(u32, @bitCast(stack.popI32()));
        stack.pushF64(@as(f64, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I64_S", pc, code, stack);
        const v = stack.popI64();
        stack.pushF64(@as(f64, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Convert_I64_U", pc, code, stack);
        const v = @as(u64, @bitCast(stack.popI64()));
        stack.pushF64(@as(f64, @floatFromInt(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Promote_F32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Promote_F32", pc, code, stack);
        const v = stack.popF32();
        stack.pushF64(@as(f64, @floatCast(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Reinterpret_F32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Reinterpret_F32", pc, code, stack);
        const v = stack.popF32();
        stack.pushI32(@as(i32, @bitCast(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Reinterpret_F64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Reinterpret_F64", pc, code, stack);
        const v = stack.popF64();
        stack.pushI64(@as(i64, @bitCast(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Reinterpret_I32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32_Reinterpret_I32", pc, code, stack);
        const v = stack.popI32();
        stack.pushF32(@as(f32, @bitCast(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Reinterpret_I64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64_Reinterpret_I64", pc, code, stack);
        const v = stack.popI64();
        stack.pushF64(@as(f64, @bitCast(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Extend8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Extend8_S", pc, code, stack);
        const v = stack.popI32();
        const v_truncated = @as(i8, @truncate(v));
        const v_extended: i32 = v_truncated;
        stack.pushI32(v_extended);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Extend16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Extend16_S", pc, code, stack);
        const v = stack.popI32();
        const v_truncated = @as(i16, @truncate(v));
        const v_extended: i32 = v_truncated;
        stack.pushI32(v_extended);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Extend8_S", pc, code, stack);
        const v = stack.popI64();
        const v_truncated = @as(i8, @truncate(v));
        const v_extended: i64 = v_truncated;
        stack.pushI64(v_extended);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Extend16_S", pc, code, stack);
        const v = stack.popI64();
        const v_truncated = @as(i16, @truncate(v));
        const v_extended: i64 = v_truncated;
        stack.pushI64(v_extended);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Extend32_S", pc, code, stack);
        const v = stack.popI64();
        const v_truncated = @as(i32, @truncate(v));
        const v_extended: i64 = v_truncated;
        stack.pushI64(v_extended);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Ref_Null(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Ref_Null", pc, code, stack);
        const valtype = code[pc].immediate.ValType;
        const val = try Val.nullRef(valtype);
        stack.pushValue(val);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Ref_Is_Null(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Ref_Is_Null", pc, code, stack);
        const val: Val = stack.popValue();
        const boolean: i32 = if (val.isNull()) 1 else 0;
        stack.pushI32(boolean);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Ref_Func(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Ref_Func", pc, code, stack);
        const func_index: u32 = code[pc].immediate.Index;
        const val = Val{ .FuncRef = .{ .index = func_index, .module_instance = stack.topFrame().module_instance } };
        stack.pushValue(val);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F32_S", pc, code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(i32, v);
        stack.pushI32(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F32_U", pc, code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F64_S", pc, code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(i32, v);
        stack.pushI32(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32_Trunc_Sat_F64_U", pc, code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(u32, v);
        stack.pushI32(@as(i32, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F32_S", pc, code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(i64, v);
        stack.pushI64(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F32_U", pc, code, stack);
        const v = stack.popF32();
        const int = OpHelpers.saturatedTruncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F64_S", pc, code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(i64, v);
        stack.pushI64(int);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64_Trunc_Sat_F64_U", pc, code, stack);
        const v = stack.popF64();
        const int = OpHelpers.saturatedTruncateTo(u64, v);
        stack.pushI64(@as(i64, @bitCast(int)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Init(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Memory_Init", pc, code, stack);
        const data_index: u32 = code[pc].immediate.Index;
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Data_Drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Data_Drop", pc, code, stack);
        const data_index: u32 = code[pc].immediate.Index;
        const data: *DataDefinition = &stack.topFrame().module_instance.module_def.datas.items[data_index];
        data.bytes.clearAndFree();
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Copy(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Memory_Copy", pc, code, stack);
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

        const source_offset = @as(usize, @intCast(source_offset_s));
        const dest_offset = @as(usize, @intCast(dest_offset_s));
        const length = @as(usize, @intCast(length_s));

        const source = buffer[source_offset .. source_offset + length];
        const destination = buffer[dest_offset .. dest_offset + length];

        if (@intFromPtr(destination.ptr) < @intFromPtr(source.ptr)) {
            std.mem.copyForwards(u8, destination, source);
        } else {
            std.mem.copyBackwards(u8, destination, source);
        }
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Fill(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Memory_Fill", pc, code, stack);
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

        const offset = @as(usize, @intCast(offset_s));
        const length = @as(usize, @intCast(length_s));

        const destination = buffer[offset .. offset + length];
        @memset(destination, value);

        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Init(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Table_Init", pc, code, stack);
        const pair: TablePairImmediates = code[pc].immediate.TablePair;
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Elem_Drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Elem_Drop", pc, code, stack);
        const elem_index: u32 = code[pc].immediate.Index;
        var elem: *ElementInstance = &stack.topFrame().module_instance.store.elements.items[elem_index];
        elem.refs.clearAndFree();
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Copy(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Table_Copy", pc, code, stack);
        const pair: TablePairImmediates = code[pc].immediate.TablePair;
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Grow(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Table_Grow", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const length = @as(u32, @bitCast(stack.popI32()));
        const init_value = stack.popValue();
        const old_length = @as(i32, @intCast(table.refs.items.len));
        const return_value: i32 = if (table.grow(length, init_value)) old_length else -1;
        stack.pushI32(return_value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Size(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Table_Size", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const length = @as(i32, @intCast(table.refs.items.len));
        stack.pushI32(length);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Fill(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("Table_Fill", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load", pc, code, stack);
        const value = try OpHelpers.loadFromMem(v128, stack, code[pc].immediate.MemoryOffset);
        stack.pushV128(value);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load8x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load8x8_S", pc, code, stack);
        try OpHelpers.vectorLoadExtend(i8, i16, 8, code[pc].immediate.MemoryOffset, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load8x8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load8x8_S", pc, code, stack);
        try OpHelpers.vectorLoadExtend(u8, i16, 8, code[pc].immediate.MemoryOffset, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load16x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load16x4_S", pc, code, stack);
        try OpHelpers.vectorLoadExtend(i16, i32, 4, code[pc].immediate.MemoryOffset, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load16x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load16x4_U", pc, code, stack);
        try OpHelpers.vectorLoadExtend(u16, i32, 4, code[pc].immediate.MemoryOffset, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load32x2_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load32x2_S", pc, code, stack);
        try OpHelpers.vectorLoadExtend(i32, i64, 2, code[pc].immediate.MemoryOffset, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load32x2_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load32x2_U", pc, code, stack);
        try OpHelpers.vectorLoadExtend(u32, i64, 2, code[pc].immediate.MemoryOffset, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load8_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load8_Splat", pc, code, stack);
        const scalar = try OpHelpers.loadFromMem(u8, stack, code[pc].immediate.MemoryOffset);
        const vec: u8x16 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load16_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load16_Splat", pc, code, stack);
        const scalar = try OpHelpers.loadFromMem(u16, stack, code[pc].immediate.MemoryOffset);
        const vec: u16x8 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load32_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load32_Splat", pc, code, stack);
        const scalar = try OpHelpers.loadFromMem(u32, stack, code[pc].immediate.MemoryOffset);
        const vec: u32x4 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load64_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load64_Splat", pc, code, stack);
        const scalar = try OpHelpers.loadFromMem(u64, stack, code[pc].immediate.MemoryOffset);
        const vec: u64x2 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Splat", pc, code, stack);
        const scalar = @as(i8, @truncate(stack.popI32()));
        const vec: i8x16 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Splat", pc, code, stack);
        const scalar = @as(i16, @truncate(stack.popI32()));
        const vec: i16x8 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Splat", pc, code, stack);
        const scalar = stack.popI32();
        const vec: i32x4 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Splat", pc, code, stack);
        const scalar = stack.popI64();
        const vec: i64x2 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Splat", pc, code, stack);
        const scalar = stack.popF32();
        const vec: f32x4 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Splat(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Splat", pc, code, stack);
        const scalar = stack.popF64();
        const vec: f64x2 = @splat(scalar);
        stack.pushV128(@as(v128, @bitCast(vec)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Extract_Lane_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Extract_Lane_S", pc, code, stack);
        OpHelpers.vectorExtractLane(i8x16, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Extract_Lane_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Extract_Lane_U", pc, code, stack);
        OpHelpers.vectorExtractLane(u8x16, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Replace_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Replace_Lane", pc, code, stack);
        OpHelpers.vectorReplaceLane(i8x16, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extract_Lane_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extract_Lane_S", pc, code, stack);
        OpHelpers.vectorExtractLane(i16x8, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extract_Lane_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extract_Lane_U", pc, code, stack);
        OpHelpers.vectorExtractLane(u16x8, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Replace_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Replace_Lane", pc, code, stack);
        OpHelpers.vectorReplaceLane(i16x8, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extract_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extract_Lane", pc, code, stack);
        OpHelpers.vectorExtractLane(i32x4, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Replace_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Replace_Lane", pc, code, stack);
        OpHelpers.vectorReplaceLane(i32x4, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Extract_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extract_Lane", pc, code, stack);
        OpHelpers.vectorExtractLane(i64x2, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Replace_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Replace_Lane", pc, code, stack);
        OpHelpers.vectorReplaceLane(i64x2, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Extract_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Extract_Lane", pc, code, stack);
        OpHelpers.vectorExtractLane(f32x4, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Replace_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Replace_Lane", pc, code, stack);
        OpHelpers.vectorReplaceLane(f32x4, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Extract_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Extract_Lane", pc, code, stack);
        OpHelpers.vectorExtractLane(f64x2, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Replace_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Replace_Lane", pc, code, stack);
        OpHelpers.vectorReplaceLane(f64x2, code[pc].immediate.Index, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_EQ", pc, code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Eq, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_NE", pc, code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Ne, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_LT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_LT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_LT_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_GT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_GT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_GT_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_LE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_LE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_LE_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_GE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i8x16, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_GE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_GE_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u8x16, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_EQ", pc, code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Eq, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_NE", pc, code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Ne, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_LT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_LT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_LT_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_GT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_GT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_GT_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_LE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_LE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_LE_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_GE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i16x8, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_GE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_GE_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u16x8, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_EQ", pc, code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Eq, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_NE", pc, code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Ne, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_LT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_LT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_LT_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_GT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_GT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_GT_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_LE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_LE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_LE_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_GE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i32x4, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_GE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_GE_U", pc, code, stack);
        OpHelpers.vectorBoolOp(u32x4, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_EQ", pc, code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Eq, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_NE", pc, code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Ne, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_LT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_LT", pc, code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_GT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_GT", pc, code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_LE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_LE", pc, code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_GE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_GE", pc, code, stack);
        OpHelpers.vectorBoolOp(f32x4, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_EQ", pc, code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Eq, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_NE", pc, code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Ne, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_LT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_LT", pc, code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_GT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_GT", pc, code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_LE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_LE", pc, code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_GE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_GE", pc, code, stack);
        OpHelpers.vectorBoolOp(f64x2, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Store", pc, code, stack);

        const value: v128 = stack.popV128();
        try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);

        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Const", pc, code, stack);
        const v: v128 = code[pc].immediate.ValueVec;
        stack.pushV128(v);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Shuffle(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shuffle", pc, code, stack);
        const v2 = @as(i8x16, @bitCast(stack.popV128()));
        const v1 = @as(i8x16, @bitCast(stack.popV128()));
        const indices: u8x16 = code[pc].immediate.VecShuffle16;

        var concat: [32]i8 = undefined;
        for (concat[0..16], 0..) |_, i| {
            concat[i] = v1[i];
            concat[i + 16] = v2[i];
        }
        const concat_v: @Vector(32, i8) = concat;

        var arr: [16]i8 = undefined;
        for (&arr, 0..) |*v, i| {
            const laneidx = indices[i];
            v.* = concat_v[laneidx];
        }
        const shuffled: i8x16 = arr;

        stack.pushV128(@as(v128, @bitCast(shuffled)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Swizzle(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Swizzle", pc, code, stack);
        const indices: i8x16 = @as(i8x16, @bitCast(stack.popV128()));
        const vec: i8x16 = @as(i8x16, @bitCast(stack.popV128()));
        var swizzled: i8x16 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            const value = if (indices[i] >= 0 and indices[i] < 16) vec[@as(usize, @intCast(indices[i]))] else @as(i8, 0);
            swizzled[i] = value;
        }
        stack.pushV128(@as(v128, @bitCast(swizzled)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Not(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Not", pc, code, stack);
        const v = @as(i8x16, @bitCast(stack.popV128()));
        const inverted = ~v;
        stack.pushV128(@as(v128, @bitCast(inverted)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_And(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_And", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .And, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_AndNot(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_AndNot", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .AndNot, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Or(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Or", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .Or, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Xor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Xor", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .Xor, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Bitselect(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Bitselect", pc, code, stack);
        const u1x128 = @Vector(128, u1);
        const c = @as(@Vector(128, bool), @bitCast(stack.popV128()));
        const v2 = @as(u1x128, @bitCast(stack.popV128()));
        const v1 = @as(u1x128, @bitCast(stack.popV128()));
        const v = @select(u1, c, v1, v2);
        stack.pushV128(@as(v128, @bitCast(v)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_AnyTrue(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_AnyTrue", pc, code, stack);
        const v = @as(u128, @bitCast(stack.popV128()));
        const boolean: i32 = if (v != 0) 1 else 0;
        stack.pushI32(boolean);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load8_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load8_Lane", pc, code, stack);
        try OpHelpers.vectorLoadLane(u8x16, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load16_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load16_Lane", pc, code, stack);
        try OpHelpers.vectorLoadLane(u16x8, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load32_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load32_Lane", pc, code, stack);
        try OpHelpers.vectorLoadLane(u32x4, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load64_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load64_Lane", pc, code, stack);
        try OpHelpers.vectorLoadLane(u64x2, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Store8_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Store8_Lane", pc, code, stack);
        try OpHelpers.vectorStoreLane(u8x16, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Store16_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Store16_Lane", pc, code, stack);
        try OpHelpers.vectorStoreLane(u16x8, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Store32_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Store32_Lane", pc, code, stack);
        try OpHelpers.vectorStoreLane(u32x4, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Store64_Lane(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Store64_Lane", pc, code, stack);
        try OpHelpers.vectorStoreLane(u64x2, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load32_Zero(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load32_Zero", pc, code, stack);
        try OpHelpers.vectorLoadLaneZero(u32x4, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_V128_Load64_Zero(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("V128_Load64_Zero", pc, code, stack);
        try OpHelpers.vectorLoadLaneZero(u64x2, code[pc], stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Demote_F64x2_Zero(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Demote_F64x2_Zero", pc, code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        var arr: [4]f32 = undefined;
        arr[0] = @as(f32, @floatCast(vec[0]));
        arr[1] = @as(f32, @floatCast(vec[1]));
        arr[2] = 0.0;
        arr[3] = 0.0;
        const demoted: f32x4 = arr;
        stack.pushV128(@as(v128, @bitCast(demoted)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Promote_Low_F32x4(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Promote_Low_F32x4", pc, code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        var arr: [2]f64 = undefined;
        arr[0] = vec[0];
        arr[1] = vec[1];
        const promoted: f64x2 = arr;
        stack.pushV128(@as(v128, @bitCast(promoted)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Abs", pc, code, stack);
        OpHelpers.vectorAbs(i8x16, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Neg", pc, code, stack);
        const vec = @as(i8x16, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Popcnt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Popcnt", pc, code, stack);
        const vec = @as(i8x16, @bitCast(stack.popV128()));
        const result: u8x16 = @popCount(vec);
        stack.pushV128(@as(v128, @bitCast(@as(v128, @bitCast(result)))));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_AllTrue(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_AllTrue", pc, code, stack);
        const boolean = OpHelpers.vectorAllTrue(i8x16, stack.popV128());
        stack.pushI32(boolean);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Bitmask(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Bitmask", pc, code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i8x16, stack.popV128());
        stack.pushI32(bitmask);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Narrow_I16x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Narrow_I16x8_S", pc, code, stack);
        OpHelpers.vectorNarrow(i16x8, i8x16, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Narrow_I16x8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Narrow_I16x8_U", pc, code, stack);
        OpHelpers.vectorNarrow(i16x8, u8x16, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Ceil(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Ceil", pc, code, stack);
        OpHelpers.vectorUnOp(f32x4, .Ceil, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Floor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Floor", pc, code, stack);
        OpHelpers.vectorUnOp(f32x4, .Floor, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Trunc(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Trunc", pc, code, stack);
        OpHelpers.vectorUnOp(f32x4, .Trunc, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Nearest(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Nearest", pc, code, stack);
        OpHelpers.vectorUnOp(f32x4, .Nearest, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shl", pc, code, stack);
        OpHelpers.vectorShift(i8x16, .Left, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shr_S", pc, code, stack);
        OpHelpers.vectorShift(i8x16, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Shr_U", pc, code, stack);
        OpHelpers.vectorShift(u8x16, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Add", pc, code, stack);
        OpHelpers.vectorBinOp(u8x16, .Add, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Add_Sat_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Add_Sat_S", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .Add_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Add_Sat_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Add_Sat_U", pc, code, stack);
        OpHelpers.vectorBinOp(u8x16, .Add_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Sub", pc, code, stack);
        OpHelpers.vectorBinOp(u8x16, .Sub, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Sub_Sat_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Sub_Sat_S", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .Sub_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Sub_Sat_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Sub_Sat_U", pc, code, stack);
        OpHelpers.vectorBinOp(u8x16, .Sub_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Ceil(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Ceil", pc, code, stack);
        OpHelpers.vectorUnOp(f64x2, .Ceil, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Floor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Floor", pc, code, stack);
        OpHelpers.vectorUnOp(f64x2, .Floor, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Min_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Min_S", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Min_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Min_U", pc, code, stack);
        OpHelpers.vectorBinOp(u8x16, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Max_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Max_S", pc, code, stack);
        OpHelpers.vectorBinOp(i8x16, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Max_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Max_U", pc, code, stack);
        OpHelpers.vectorBinOp(u8x16, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Trunc(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Trunc", pc, code, stack);
        OpHelpers.vectorUnOp(f64x2, .Trunc, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I8x16_Avgr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I8x16_Avgr_U", pc, code, stack);
        OpHelpers.vectorAvgrU(u8x16, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extadd_Pairwise_I8x16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extadd_Pairwise_I8x16_S", pc, code, stack);
        OpHelpers.vectorAddPairwise(i8x16, i16x8, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extadd_Pairwise_I8x16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extadd_Pairwise_I8x16_U", pc, code, stack);
        OpHelpers.vectorAddPairwise(u8x16, u16x8, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extadd_Pairwise_I16x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extadd_Pairwise_I16x8_S", pc, code, stack);
        OpHelpers.vectorAddPairwise(i16x8, i32x4, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extadd_Pairwise_I16x8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extadd_Pairwise_I16x8_U", pc, code, stack);
        OpHelpers.vectorAddPairwise(u16x8, u32x4, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Abs", pc, code, stack);
        OpHelpers.vectorAbs(i16x8, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Neg", pc, code, stack);
        const vec = @as(u16x8, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Q15mulr_Sat_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Q15mulr_Sat_S", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_AllTrue(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_AllTrue", pc, code, stack);
        const boolean: i32 = OpHelpers.vectorAllTrue(i16x8, stack.popV128());
        stack.pushI32(boolean);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Bitmask(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Bitmask", pc, code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i16x8, stack.popV128());
        stack.pushI32(bitmask);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Narrow_I32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Narrow_I32x4_S", pc, code, stack);
        OpHelpers.vectorNarrow(i32x4, i16x8, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Narrow_I32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Narrow_I32x4_U", pc, code, stack);
        OpHelpers.vectorNarrow(i32x4, u16x8, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extend_Low_I8x16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_Low_I8x16_S", pc, code, stack);
        OpHelpers.vectorExtend(i8x16, i16x8, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extend_High_I8x16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_High_I8x16_S", pc, code, stack);
        OpHelpers.vectorExtend(i8x16, i16x8, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extend_Low_I8x16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_Low_I8x16_U", pc, code, stack);
        OpHelpers.vectorExtend(u8x16, i16x8, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }
    fn op_I16x8_Extend_High_I8x16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extend_High_I8x16_U", pc, code, stack);
        OpHelpers.vectorExtend(u8x16, i16x8, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Shl", pc, code, stack);
        OpHelpers.vectorShift(i16x8, .Left, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Shr_S", pc, code, stack);
        OpHelpers.vectorShift(i16x8, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Shr_U", pc, code, stack);
        OpHelpers.vectorShift(u16x8, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Add", pc, code, stack);
        OpHelpers.vectorBinOp(i16x8, .Add, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Add_Sat_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Add_Sat_S", pc, code, stack);
        OpHelpers.vectorBinOp(i16x8, .Add_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Add_Sat_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Add_Sat_U", pc, code, stack);
        OpHelpers.vectorBinOp(u16x8, .Add_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Sub", pc, code, stack);
        OpHelpers.vectorBinOp(i16x8, .Sub, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Sub_Sat_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Sub_Sat_S", pc, code, stack);
        OpHelpers.vectorBinOp(i16x8, .Sub_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Sub_Sat_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Sub_Sat_U", pc, code, stack);
        OpHelpers.vectorBinOp(u16x8, .Sub_Sat, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Nearest(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Nearest", pc, code, stack);
        OpHelpers.vectorUnOp(f64x2, .Nearest, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Mul", pc, code, stack);
        OpHelpers.vectorBinOp(i16x8, .Mul, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Min_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Min_S", pc, code, stack);
        OpHelpers.vectorBinOp(i16x8, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Min_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Min_U", pc, code, stack);
        OpHelpers.vectorBinOp(u16x8, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Max_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Max_S", pc, code, stack);
        OpHelpers.vectorBinOp(i16x8, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Max_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Max_U", pc, code, stack);
        OpHelpers.vectorBinOp(u16x8, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Avgr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Avgr_U", pc, code, stack);
        OpHelpers.vectorAvgrU(u16x8, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extmul_Low_I8x16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_Low_I8x16_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(i8x16, i16x8, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extmul_High_I8x16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_High_I8x16_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(i8x16, i16x8, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extmul_Low_I8x16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_Low_I8x16_U", pc, code, stack);
        OpHelpers.vectorMulPairwise(u8x16, u16x8, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I16x8_Extmul_High_I8x16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I16x8_Extmul_High_I8x16_U", pc, code, stack);
        OpHelpers.vectorMulPairwise(u8x16, u16x8, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Abs", pc, code, stack);
        OpHelpers.vectorAbs(i32x4, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Neg", pc, code, stack);
        const vec = @as(i32x4, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_AllTrue(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_AllTrue", pc, code, stack);
        const boolean: i32 = OpHelpers.vectorAllTrue(i32x4, stack.popV128());
        stack.pushI32(boolean);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Bitmask(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Bitmask", pc, code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i32x4, stack.popV128());
        stack.pushI32(bitmask);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extend_Low_I16x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_Low_I16x8_S", pc, code, stack);
        OpHelpers.vectorExtend(i16x8, i32x4, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extend_High_I16x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_High_I16x8_S", pc, code, stack);
        OpHelpers.vectorExtend(i16x8, i32x4, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extend_Low_I16x8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_Low_I16x8_U", pc, code, stack);
        OpHelpers.vectorExtend(u16x8, i32x4, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extend_High_I16x8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extend_High_I16x8_U", pc, code, stack);
        OpHelpers.vectorExtend(u16x8, i32x4, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Shl", pc, code, stack);
        OpHelpers.vectorShift(i32x4, .Left, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Shr_S", pc, code, stack);
        OpHelpers.vectorShift(i32x4, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Shr_U", pc, code, stack);
        OpHelpers.vectorShift(u32x4, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Abs", pc, code, stack);
        OpHelpers.vectorAbs(i64x2, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Neg", pc, code, stack);
        const vec = @as(i64x2, @bitCast(stack.popV128()));
        const negated = -%vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_AllTrue(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_AllTrue", pc, code, stack);
        const boolean = OpHelpers.vectorAllTrue(i64x2, stack.popV128());
        stack.pushI32(boolean);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Bitmask(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Bitmask", pc, code, stack);
        const bitmask: i32 = OpHelpers.vectorBitmask(i64x2, stack.popV128());
        stack.pushI32(bitmask);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Extend_Low_I32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_Low_I32x4_S", pc, code, stack);
        OpHelpers.vectorExtend(i32x4, i64x2, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Extend_High_I32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_High_I32x4_S", pc, code, stack);
        OpHelpers.vectorExtend(i32x4, i64x2, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Extend_Low_I32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_Low_I32x4_U", pc, code, stack);
        OpHelpers.vectorExtend(u32x4, i64x2, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Extend_High_I32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Extend_High_I32x4_U", pc, code, stack);
        OpHelpers.vectorExtend(u32x4, i64x2, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Shl", pc, code, stack);
        OpHelpers.vectorShift(i64x2, .Left, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Shr_S", pc, code, stack);
        OpHelpers.vectorShift(i64x2, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Shr_U", pc, code, stack);
        OpHelpers.vectorShift(u64x2, .Right, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Add", pc, code, stack);
        OpHelpers.vectorBinOp(i32x4, .Add, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Sub", pc, code, stack);
        OpHelpers.vectorBinOp(i32x4, .Sub, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Mul", pc, code, stack);
        OpHelpers.vectorBinOp(i32x4, .Mul, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Min_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Min_S", pc, code, stack);
        OpHelpers.vectorBinOp(i32x4, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Min_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Min_U", pc, code, stack);
        OpHelpers.vectorBinOp(u32x4, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Max_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Max_S", pc, code, stack);
        OpHelpers.vectorBinOp(i32x4, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Max_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Max_U", pc, code, stack);
        OpHelpers.vectorBinOp(u32x4, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Dot_I16x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Dot_I16x8_S", pc, code, stack);
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
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extmul_Low_I16x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_Low_I16x8_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(i16x8, i32x4, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extmul_High_I16x8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_High_I16x8_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(i16x8, i32x4, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extmul_Low_I16x8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_Low_I16x8_U", pc, code, stack);
        OpHelpers.vectorMulPairwise(u16x8, u32x4, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Extmul_High_I16x8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Extmul_High_I16x8_U", pc, code, stack);
        OpHelpers.vectorMulPairwise(u16x8, u32x4, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Add", pc, code, stack);
        OpHelpers.vectorBinOp(i64x2, .Add, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Sub", pc, code, stack);
        OpHelpers.vectorBinOp(i64x2, .Sub, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_Mul", pc, code, stack);
        OpHelpers.vectorBinOp(i64x2, .Mul, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_EQ", pc, code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Eq, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_NE", pc, code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Ne, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_LT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Lt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_GT_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Gt, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_LE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Le, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", pc, code, stack);
        OpHelpers.vectorBoolOp(i64x2, .Ge, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64x2_Extmul_Low_I32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(i32x4, i64x2, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }
    fn op_I64x2_Extmul_High_I32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(i32x4, i64x2, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }
    fn op_I64x2_Extmul_Low_I32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(u32x4, u64x2, .Low, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }
    fn op_I64x2_Extmul_High_I32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I64x2_GE_S", pc, code, stack);
        OpHelpers.vectorMulPairwise(u32x4, u64x2, .High, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Abs", pc, code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        const abs = @abs(vec);
        stack.pushV128(@as(v128, @bitCast(abs)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Neg", pc, code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        const negated = -vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Sqrt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Sqrt", pc, code, stack);
        const vec = @as(f32x4, @bitCast(stack.popV128()));
        const root = @sqrt(vec);
        stack.pushV128(@as(v128, @bitCast(root)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Add", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .Add, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Sub", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .Sub, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Mul", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .Mul, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Div", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .Div, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Min(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Min", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Max(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Max", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_PMin(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_PMin", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .PMin, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_PMax(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_PMax", pc, code, stack);
        OpHelpers.vectorBinOp(f32x4, .PMax, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Abs", pc, code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        const abs = @abs(vec);
        stack.pushV128(@as(v128, @bitCast(abs)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Neg", pc, code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        const negated = -vec;
        stack.pushV128(@as(v128, @bitCast(negated)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Sqrt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Sqrt", pc, code, stack);
        const vec = @as(f64x2, @bitCast(stack.popV128()));
        const root = @sqrt(vec);
        stack.pushV128(@as(v128, @bitCast(root)));
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Add", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .Add, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Sub", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .Sub, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Mul", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .Mul, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Div", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .Div, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Min(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Min", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .Min, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Max(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Max", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .Max, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_PMin(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_PMin", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .PMin, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_PMax(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_PMax", pc, code, stack);
        OpHelpers.vectorBinOp(f64x2, .PMax, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Trunc_Sat_F32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Trunc_Sat_F32x4_S", pc, code, stack);
        OpHelpers.vectorConvert(f32x4, i32x4, .Low, .Saturate, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Trunc_Sat_F32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Trunc_Sat_F32x4_U", pc, code, stack);
        OpHelpers.vectorConvert(f32x4, u32x4, .Low, .Saturate, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Convert_I32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Convert_I32x4_S", pc, code, stack);
        OpHelpers.vectorConvert(i32x4, f32x4, .Low, .SafeCast, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32x4_Convert_I32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F32x4_Convert_I32x4_U", pc, code, stack);
        OpHelpers.vectorConvert(u32x4, f32x4, .Low, .SafeCast, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Trunc_Sat_F64x2_S_Zero(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Trunc_Sat_F64x2_S_Zero", pc, code, stack);
        OpHelpers.vectorConvert(f64x2, i32x4, .Low, .Saturate, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32x4_Trunc_Sat_F64x2_U_Zero(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("I32x4_Trunc_Sat_F64x2_U_Zero", pc, code, stack);
        OpHelpers.vectorConvert(f64x2, u32x4, .Low, .Saturate, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Convert_Low_I32x4_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Convert_Low_I32x4_S", pc, code, stack);
        OpHelpers.vectorConvert(i32x4, f64x2, .Low, .SafeCast, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64x2_Convert_Low_I32x4_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try preamble("F64x2_Convert_Low_I32x4_U", pc, code, stack);
        OpHelpers.vectorConvert(u32x4, f64x2, .Low, .SafeCast, stack);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
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
        pc: u32 = 0,
        trap_counter: u32 = 0, // used for trapping on step
        is_invoking: bool = false,

        fn onInvokeFinished(state: *DebugState) void {
            state.pc = 0;
            state.is_invoking = false;
            state.trap_counter = 0;
        }
    };

    const MeterState = if (metering.enabled) struct {
        pc: u32 = 0,
        opcode: Opcode = Opcode.Invalid,
        meter: metering.Meter,
        enabled: bool = false,

        fn onInvokeFinished(state: *MeterState) void {
            state.pc = 0;
        }
    } else void;

    stack: Stack,
    functions: std.ArrayList(FunctionInstance),
    debug_state: ?DebugState,
    meter_state: MeterState,

    pub fn fromVM(vm: *VM) *StackVM {
        return @as(*StackVM, @alignCast(@ptrCast(vm.impl)));
    }

    pub fn init(vm: *VM) void {
        var self: *StackVM = fromVM(vm);
        self.stack = Stack.init(vm.allocator);
        self.functions = std.ArrayList(FunctionInstance).init(vm.allocator);
        self.debug_state = null;
    }

    pub fn deinit(vm: *VM) void {
        var self: *StackVM = fromVM(vm);

        self.functions.deinit();

        self.stack.deinit();
        if (self.debug_state) |*debug_state| {
            debug_state.trapped_opcodes.deinit();
        }
    }

    pub fn instantiate(vm: *VM, module: *ModuleInstance, opts: ModuleInstantiateOpts) anyerror!void {
        var self: *StackVM = fromVM(vm);

        if (opts.enable_debug) {
            self.debug_state = DebugState{
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

        try self.functions.ensureTotalCapacity(module.module_def.functions.items.len);
        for (module.module_def.functions.items, 0..) |*def_func, i| {
            const func_type: *const FunctionTypeDefinition = &module.module_def.types.items[def_func.type_index];
            const param_types: []const ValType = func_type.getParams();

            const num_locals: u32 = @intCast(def_func.locals.items.len);
            const num_params: u16 = @intCast(param_types.len);
            const num_values: u32 = @intCast(def_func.stack_stats.values);

            const f = FunctionInstance{
                .type_def_index = def_func.type_index,
                .def_index = @as(u32, @intCast(i)),
                .code = module.module_def.code.instructions.items.ptr,
                .instructions_begin = def_func.instructions_begin,
                .num_locals = num_locals,
                .num_params = num_params,
                .num_returns = @intCast(func_type.getReturns().len),

                // maximum number of values that can be on the stack for this function
                .max_values = num_values + num_locals + num_params,
                .max_labels = @intCast(def_func.stack_stats.labels),
            };
            try self.functions.append(f);
        }
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

        var pc: u32 = 0;
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

        const params_slice = params[0..func.num_params];
        var returns_slice = returns[0..func.num_returns];

        // Ensure any leftover stack state doesn't pollute this invoke. Can happen if the previous invoke returned an error.
        self.stack.popAll();

        // pushFrame() assumes the stack already contains the params to the function, so ensure they exist
        // on the value stack
        for (params_slice) |v| {
            self.stack.pushValue(v);
        }

        try self.stack.pushFrame(&func, module);
        self.stack.pushLabel(func.num_returns, @intCast(func_def.continuation));

        DebugTrace.traceFunction(module, self.stack.num_frames, func.def_index);

        try InstructionFuncs.run(@intCast(func.instructions_begin), func.code, &self.stack);

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

                try data.callback(data.userdata, module, params, returns);
            },
            .Wasm => |data| {
                var import_instance: *ModuleInstance = data.module_instance;
                const handle: FunctionHandle = try import_instance.getFunctionHandle(func_import.name); // TODO could cache this in the func_import
                try import_instance.vm.invoke(import_instance, handle, params, returns, opts);
            },
        }
    }
};
