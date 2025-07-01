const std = @import("std");
const assert = std.debug.assert;

const opcodes = @import("opcode.zig");
const Opcode = opcodes.Opcode;

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
const BranchTableImmediates = def.BranchTableImmediates;
const CallIndirectImmediates = def.CallIndirectImmediates;
const DataDefinition = def.DataDefinition;
const FunctionDefinition = def.FunctionDefinition;
const FunctionHandle = def.FunctionHandle;
const FunctionTypeDefinition = def.FunctionTypeDefinition;
const Instruction = def.Instruction;
const NameCustomSection = def.NameCustomSection;
const TablePairImmediates = def.TablePairImmediates;
const Val = def.Val;
const ValType = def.ValType;

const inst = @import("instance.zig");
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

inline fn preamble(name: []const u8, pc: u32, code: [*]const Instruction, stack: *Stack) !void {
    return shared.preamble(StackVM, name, pc, code, stack);
}

fn op_DebugTrap(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
    try preamble("DebugTrap", pc, code, stack);
    const root_module_instance: *ModuleInstance = stack.frames[0].module_instance;
    const stack_vm = StackVM.fromVM(root_module_instance.vm);

    std.debug.assert(stack_vm.debug_state != null);
    stack_vm.debug_state.?.pc = pc;

    return error.TrapDebug;
}

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
                .code = module.module_def.code.instructions.items.ptr,
                .def_index = @as(u32, @intCast(i)),
                .instructions_begin = def_func.instructions_begin,
                .num_locals = @intCast(def_func.locals.items.len),
                .num_params = @intCast(param_types.len),
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
            assert(debug_state.is_invoking);
            pc = debug_state.pc;
            for (debug_state.trapped_opcodes.items) |op| {
                if (op.address == debug_state.pc) {
                    opcode = op.opcode;
                    break;
                }
            }
            unreachable; // Should never get into a state where a trapped opcode doesn't have an associated record

        } else if (metering.enabled) {
            assert(self.meter_state.enabled);
            pc = self.meter_state.pc;
            if (opts.meter != metering.initial_meter) {
                self.meter_state.meter = opts.meter;
            }
            opcode = self.meter_state.opcode;
        } else {
            // There was no debug or meter information, so nothing to resume.
            return error.TrapInvalidResume;
        }

        try self.run(module, pc);

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

        assert(self.debug_state != null);
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

        try self.run(module, @intCast(func.instructions_begin));

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

    fn run(self: *StackVM, module: *ModuleInstance, start_pc: u32) anyerror!void {
        var pc: u32 = start_pc;
        var code: [*]const Instruction = module.module_def.code.instructions.items.ptr;
        var stack = &self.stack;

        interpret: switch (code[pc].opcode) {
            Opcode.Invalid => unreachable,
            Opcode.Unreachable => return error.TrapUnreachable,
            Opcode.DebugTrap => return op_DebugTrap(pc, code, stack),
            Opcode.Noop => {
                try preamble("Noop", pc, code, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
            Opcode.Block => {
                try preamble("Block", pc, code, stack);
                const block = code[pc].immediate.Block;
                stack.pushLabel(block.num_returns, block.continuation);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
            Opcode.Loop => {
                try preamble("Loop", pc, code, stack);
                const block = code[pc].immediate.Block;
                stack.pushLabel(block.num_returns, block.continuation);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
            Opcode.If => {
                try preamble("If", pc, code, stack);
                pc = try OpHelpers.ifCond(stack, pc, code);
                continue :interpret code[pc].opcode;
            },
            Opcode.IfNoElse => {
                try preamble("If", pc, code, stack);
                pc = try OpHelpers.ifNoElse(stack, pc, code);
                continue :interpret code[pc].opcode;
            },
            Opcode.Else => {
                try preamble("Else", pc, code, stack);

                pc = code[pc].immediate.If.end_continuation;
                continue :interpret code[pc].opcode;
            },
            Opcode.End => {
                try preamble("End", pc, code, stack);
                const next = OpHelpers.end(stack, pc, code) orelse return;

                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },
            Opcode.Branch => {
                try preamble("Branch", pc, code, stack);
                const label_id: u32 = code[pc].immediate.LabelId;
                const next: FuncCallData = OpHelpers.branch(stack, label_id) orelse return;
                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },

            Opcode.Branch_If => {
                try preamble("Branch_If", pc, code, stack);
                const next = OpHelpers.branchIf(stack, pc, code) orelse return;
                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },

            Opcode.Branch_Table => {
                try preamble("Branch_Table", pc, code, stack);
                const next = OpHelpers.branchTable(stack, code[pc]) orelse return;
                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },

            Opcode.Return => {
                try preamble("Return", pc, code, stack);
                const next: FuncCallData = stack.popFrame() orelse return;
                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },

            Opcode.Call_Local => {
                try preamble("Call", pc, code, stack);

                const next = try OpHelpers.callLocal(StackVM, stack, pc, code);

                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },

            Opcode.Call_Indirect => {
                try preamble("Call_Indirect", pc, code, stack);
                const next = try OpHelpers.callIndirect(StackVM, stack, pc, code);
                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },

            Opcode.Call_Import => {
                try preamble("Call_Import", pc, code, stack);
                const next = try OpHelpers.callImport(StackVM, stack, pc, code);
                pc = next.continuation;
                code = next.code;
                continue :interpret code[pc].opcode;
            },

            Opcode.Drop => {
                try preamble("Drop", pc, code, stack);
                _ = stack.popValue();
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Select => {
                try preamble("Select", pc, code, stack);
                stack.select();

                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Select_T => {
                try preamble("Select_T", pc, code, stack);

                stack.selectT();

                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Local_Get => {
                try preamble("Local_Get", pc, code, stack);
                OpHelpers.localGet(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Local_Set => {
                try preamble("Local_Set", pc, code, stack);
                try OpHelpers.localSet(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Local_Tee => {
                try preamble("Local_Tee", pc, code, stack);
                try OpHelpers.localTee(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Global_Get => {
                try preamble("Global_Get", pc, code, stack);
                OpHelpers.globalGet(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Global_Set => {
                try preamble("Global_Set", pc, code, stack);
                try OpHelpers.globalSet(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Table_Get => {
                try preamble("Table_Get", pc, code, stack);
                try OpHelpers.tableGet(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Table_Set => {
                try preamble("Table_Set", pc, code, stack);
                try OpHelpers.tableSet(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Load => {
                try preamble("I32_Load", pc, code, stack);
                const value = try OpHelpers.loadFromMem(i32, stack, code[pc].immediate.MemoryOffset);
                stack.pushI32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Load => {
                try preamble("I64_Load", pc, code, stack);
                const value = try OpHelpers.loadFromMem(i64, stack, code[pc].immediate.MemoryOffset);
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Load => {
                try preamble("F32_Load", pc, code, stack);
                const value = try OpHelpers.loadFromMem(f32, stack, code[pc].immediate.MemoryOffset);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Load => {
                try preamble("F64_Load", pc, code, stack);
                const value = try OpHelpers.loadFromMem(f64, stack, code[pc].immediate.MemoryOffset);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Load8_S => {
                try preamble("I32_Load8_S", pc, code, stack);
                const value: i32 = try OpHelpers.loadFromMem(i8, stack, code[pc].immediate.MemoryOffset);
                stack.pushI32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Load8_U => {
                try preamble("I32_Load8_U", pc, code, stack);
                const value: u32 = try OpHelpers.loadFromMem(u8, stack, code[pc].immediate.MemoryOffset);
                stack.pushI32(@as(i32, @bitCast(value)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Load16_S => {
                try preamble("I32_Load16_S", pc, code, stack);
                const value: i32 = try OpHelpers.loadFromMem(i16, stack, code[pc].immediate.MemoryOffset);
                stack.pushI32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Load16_U => {
                try preamble("I32_Load16_U", pc, code, stack);
                const value: u32 = try OpHelpers.loadFromMem(u16, stack, code[pc].immediate.MemoryOffset);
                stack.pushI32(@as(i32, @bitCast(value)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Load8_S => {
                try preamble("I64_Load8_S", pc, code, stack);
                const value: i64 = try OpHelpers.loadFromMem(i8, stack, code[pc].immediate.MemoryOffset);
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Load8_U => {
                try preamble("I64_Load8_U", pc, code, stack);
                const value: u64 = try OpHelpers.loadFromMem(u8, stack, code[pc].immediate.MemoryOffset);
                stack.pushI64(@as(i64, @bitCast(value)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Load16_S => {
                try preamble("I64_Load16_S", pc, code, stack);
                const value: i64 = try OpHelpers.loadFromMem(i16, stack, code[pc].immediate.MemoryOffset);
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Load16_U => {
                try preamble("I64_Load16_U", pc, code, stack);
                const value: u64 = try OpHelpers.loadFromMem(u16, stack, code[pc].immediate.MemoryOffset);
                stack.pushI64(@as(i64, @bitCast(value)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Load32_S => {
                try preamble("I64_Load32_S", pc, code, stack);
                const value: i64 = try OpHelpers.loadFromMem(i32, stack, code[pc].immediate.MemoryOffset);
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Load32_U => {
                try preamble("I64_Load32_U", pc, code, stack);
                const value: u64 = try OpHelpers.loadFromMem(u32, stack, code[pc].immediate.MemoryOffset);
                stack.pushI64(@as(i64, @bitCast(value)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Store => {
                try preamble("I32_Store", pc, code, stack);
                const value: i32 = stack.popI32();
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Store => {
                try preamble("I64_Store", pc, code, stack);
                const value: i64 = stack.popI64();
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Store => {
                try preamble("F32_Store", pc, code, stack);
                const value: f32 = stack.popF32();
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Store => {
                try preamble("F64_Store", pc, code, stack);
                const value: f64 = stack.popF64();
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Store8 => {
                try preamble("I32_Store8", pc, code, stack);
                const value: i8 = @as(i8, @truncate(stack.popI32()));
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Store16 => {
                try preamble("I32_Store16", pc, code, stack);
                const value: i16 = @as(i16, @truncate(stack.popI32()));
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Store8 => {
                try preamble("I64_Store8", pc, code, stack);
                const value: i8 = @as(i8, @truncate(stack.popI64()));
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Store16 => {
                try preamble("I64_Store16", pc, code, stack);
                const value: i16 = @as(i16, @truncate(stack.popI64()));
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Store32 => {
                try preamble("I64_Store32", pc, code, stack);
                const value: i32 = @as(i32, @truncate(stack.popI64()));
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Memory_Size => {
                try preamble("Memory_Size", pc, code, stack);
                OpHelpers.memSize(stack);

                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Memory_Grow => {
                try preamble("Memory_Grow", pc, code, stack);
                OpHelpers.memGrow(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Const => {
                try preamble("I32_Const", pc, code, stack);
                OpHelpers.i32Const(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Const => {
                try preamble("I64_Const", pc, code, stack);
                OpHelpers.i64Const(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Const => {
                try preamble("F32_Const", pc, code, stack);
                OpHelpers.f32Const(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Const => {
                try preamble("F64_Const", pc, code, stack);
                OpHelpers.f64Const(stack, code[pc]);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Eqz => {
                try preamble("I32_Eqz", pc, code, stack);
                OpHelpers.i32Eqz(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Eq => {
                try preamble("I32_Eq", pc, code, stack);
                OpHelpers.i32Eq(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_NE => {
                try preamble("I32_NE", pc, code, stack);
                OpHelpers.i32Ne(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_LT_S => {
                try preamble("I32_LT_S", pc, code, stack);
                OpHelpers.i32LtS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_LT_U => {
                try preamble("I32_LT_U", pc, code, stack);
                OpHelpers.i32LtU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_GT_S => {
                try preamble("I32_GT_S", pc, code, stack);
                OpHelpers.i32GtS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_GT_U => {
                try preamble("I32_GT_U", pc, code, stack);
                OpHelpers.i32GtU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_LE_S => {
                try preamble("I32_LE_S", pc, code, stack);
                OpHelpers.i32LeS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_LE_U => {
                try preamble("I32_LE_U", pc, code, stack);
                OpHelpers.i32LeU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_GE_S => {
                try preamble("I32_GE_S", pc, code, stack);
                OpHelpers.i32GeS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_GE_U => {
                try preamble("I32_GE_U", pc, code, stack);
                OpHelpers.i32GeU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Eqz => {
                try preamble("I64_Eqz", pc, code, stack);
                OpHelpers.i64Eqz(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Eq => {
                try preamble("I64_Eq", pc, code, stack);
                OpHelpers.i64Eq(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_NE => {
                try preamble("I64_NE", pc, code, stack);
                OpHelpers.i64Ne(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_LT_S => {
                try preamble("I64_LT_S", pc, code, stack);
                OpHelpers.i64LtS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_LT_U => {
                try preamble("I64_LT_U", pc, code, stack);
                OpHelpers.i64LtU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_GT_S => {
                try preamble("I64_GT_S", pc, code, stack);
                OpHelpers.i64GtS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_GT_U => {
                try preamble("I64_GT_U", pc, code, stack);
                OpHelpers.i64GtU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_LE_S => {
                try preamble("I64_LE_S", pc, code, stack);
                OpHelpers.i64LeS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_LE_U => {
                try preamble("I64_LE_U", pc, code, stack);
                OpHelpers.i64LeU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_GE_S => {
                try preamble("I64_GE_S", pc, code, stack);
                OpHelpers.i64GeS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_GE_U => {
                try preamble("I64_GE_U", pc, code, stack);
                OpHelpers.i64GeU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_EQ => {
                try preamble("F32_EQ", pc, code, stack);
                OpHelpers.f32Eq(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_NE => {
                try preamble("F32_NE", pc, code, stack);
                OpHelpers.f32Ne(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_LT => {
                try preamble("F32_LT", pc, code, stack);
                OpHelpers.f32Lt(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_GT => {
                try preamble("F32_GT", pc, code, stack);
                OpHelpers.f32Gt(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_LE => {
                try preamble("F32_LE", pc, code, stack);
                OpHelpers.f32Le(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_GE => {
                try preamble("F32_GE", pc, code, stack);
                OpHelpers.f32Ge(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_EQ => {
                try preamble("F64_EQ", pc, code, stack);
                OpHelpers.f64Eq(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_NE => {
                try preamble("F64_NE", pc, code, stack);
                OpHelpers.f64Ne(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_LT => {
                try preamble("F64_LT", pc, code, stack);
                OpHelpers.f64Lt(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_GT => {
                try preamble("F64_GT", pc, code, stack);
                OpHelpers.f64Gt(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_LE => {
                try preamble("F64_LE", pc, code, stack);
                OpHelpers.f64Le(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_GE => {
                try preamble("F64_GE", pc, code, stack);
                OpHelpers.f64Ge(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Clz => {
                try preamble("I32_Clz", pc, code, stack);
                OpHelpers.i32Clz(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Ctz => {
                try preamble("I32_Ctz", pc, code, stack);
                OpHelpers.i32Ctz(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Popcnt => {
                try preamble("I32_Popcnt", pc, code, stack);
                OpHelpers.i32Popcnt(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Add => {
                try preamble("I32_Add", pc, code, stack);
                OpHelpers.i32Add(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Sub => {
                try preamble("I32_Sub", pc, code, stack);
                OpHelpers.i32Sub(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Mul => {
                try preamble("I32_Mul", pc, code, stack);
                OpHelpers.i32Mul(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Div_S => {
                try preamble("I32_Div_S", pc, code, stack);
                try OpHelpers.i32DivS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Div_U => {
                try preamble("I32_Div_U", pc, code, stack);
                try OpHelpers.i32DivU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Rem_S => {
                try preamble("I32_Rem_S", pc, code, stack);
                try OpHelpers.i32RemS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Rem_U => {
                try preamble("I32_Rem_U", pc, code, stack);
                try OpHelpers.i32RemU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_And => {
                try preamble("I32_And", pc, code, stack);
                OpHelpers.i32And(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Or => {
                try preamble("I32_Or", pc, code, stack);
                OpHelpers.i32Or(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Xor => {
                try preamble("I32_Xor", pc, code, stack);
                OpHelpers.i32Xor(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Shl => {
                try preamble("I32_Shl", pc, code, stack);
                try OpHelpers.i32Shl(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Shr_S => {
                try preamble("I32_Shr_S", pc, code, stack);
                try OpHelpers.i32ShrS(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Shr_U => {
                try preamble("I32_Shr_U", pc, code, stack);
                try OpHelpers.i32ShrU(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Rotl => {
                try preamble("I32_Rotl", pc, code, stack);
                OpHelpers.i32Rotl(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Rotr => {
                try preamble("I32_Rotr", pc, code, stack);
                OpHelpers.i32Rotr(stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Clz => {
                try preamble("I64_Clz", pc, code, stack);
                const v: i64 = stack.popI64();
                const num_zeroes = @clz(v);
                stack.pushI64(num_zeroes);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Ctz => {
                try preamble("I64_Ctz", pc, code, stack);
                const v: i64 = stack.popI64();
                const num_zeroes = @ctz(v);
                stack.pushI64(num_zeroes);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Popcnt => {
                try preamble("I64_Popcnt", pc, code, stack);
                const v: i64 = stack.popI64();
                const num_bits_set = @popCount(v);
                stack.pushI64(num_bits_set);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Add => {
                try preamble("I64_Add", pc, code, stack);
                const v2: i64 = stack.popI64();
                const v1: i64 = stack.popI64();
                const result = v1 +% v2;
                stack.pushI64(result);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Sub => {
                try preamble("I64_Sub", pc, code, stack);
                const v2: i64 = stack.popI64();
                const v1: i64 = stack.popI64();
                const result = v1 -% v2;
                stack.pushI64(result);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Mul => {
                try preamble("I64_Mul", pc, code, stack);
                const v2: i64 = stack.popI64();
                const v1: i64 = stack.popI64();
                const value = v1 *% v2;
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Div_S => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Div_U => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Rem_S => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Rem_U => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_And => {
                try preamble("I64_And", pc, code, stack);
                const v2: u64 = @as(u64, @bitCast(stack.popI64()));
                const v1: u64 = @as(u64, @bitCast(stack.popI64()));
                const value = @as(i64, @bitCast(v1 & v2));
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Or => {
                try preamble("I64_Or", pc, code, stack);
                const v2: u64 = @as(u64, @bitCast(stack.popI64()));
                const v1: u64 = @as(u64, @bitCast(stack.popI64()));
                const value = @as(i64, @bitCast(v1 | v2));
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Xor => {
                try preamble("I64_Xor", pc, code, stack);
                const v2: u64 = @as(u64, @bitCast(stack.popI64()));
                const v1: u64 = @as(u64, @bitCast(stack.popI64()));
                const value = @as(i64, @bitCast(v1 ^ v2));
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Shl => {
                try preamble("I64_Shl", pc, code, stack);
                const shift_unsafe: i64 = stack.popI64();
                const int: i64 = stack.popI64();
                const shift: i64 = try std.math.mod(i64, shift_unsafe, 64);
                const value = std.math.shl(i64, int, shift);
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Shr_S => {
                try preamble("I64_Shr_S", pc, code, stack);
                const shift_unsafe: i64 = stack.popI64();
                const int: i64 = stack.popI64();
                const shift = try std.math.mod(i64, shift_unsafe, 64);
                const value = std.math.shr(i64, int, shift);
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Shr_U => {
                try preamble("I64_Shr_U", pc, code, stack);
                const shift_unsafe: u64 = @as(u64, @bitCast(stack.popI64()));
                const int: u64 = @as(u64, @bitCast(stack.popI64()));
                const shift = try std.math.mod(u64, shift_unsafe, 64);
                const value = @as(i64, @bitCast(std.math.shr(u64, int, shift)));
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Rotl => {
                try preamble("I64_Rotl", pc, code, stack);
                const rot: u64 = @as(u64, @bitCast(stack.popI64()));
                const int: u64 = @as(u64, @bitCast(stack.popI64()));
                const value = @as(i64, @bitCast(std.math.rotl(u64, int, rot)));
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Rotr => {
                try preamble("I64_Rotr", pc, code, stack);
                const rot: u64 = @as(u64, @bitCast(stack.popI64()));
                const int: u64 = @as(u64, @bitCast(stack.popI64()));
                const value = @as(i64, @bitCast(std.math.rotr(u64, int, rot)));
                stack.pushI64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Abs => {
                try preamble("F32_Abs", pc, code, stack);
                const f = stack.popF32();
                const value = @abs(f);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Neg => {
                try preamble("F32_Neg", pc, code, stack);
                const f = stack.popF32();
                stack.pushF32(-f);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Ceil => {
                try preamble("F32_Ceil", pc, code, stack);
                const f = stack.popF32();
                const value = @ceil(f);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Floor => {
                try preamble("F32_Floor", pc, code, stack);
                const f = stack.popF32();
                const value = @floor(f);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Trunc => {
                try preamble("F32_Trunc", pc, code, stack);
                const f = stack.popF32();
                const value = std.math.trunc(f);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Nearest => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Sqrt => {
                try preamble("F32_Sqrt", pc, code, stack);
                const f = stack.popF32();
                const value = std.math.sqrt(f);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Add => {
                try preamble("F32_Add", pc, code, stack);
                const v2 = stack.popF32();
                const v1 = stack.popF32();
                const value = v1 + v2;
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Sub => {
                try preamble("F32_Sub", pc, code, stack);
                const v2 = stack.popF32();
                const v1 = stack.popF32();
                const value = v1 - v2;
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Mul => {
                try preamble("F32_Mul", pc, code, stack);
                const v2 = stack.popF32();
                const v1 = stack.popF32();
                const value = v1 * v2;
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Div => {
                try preamble("F32_Div", pc, code, stack);
                const v2 = stack.popF32();
                const v1 = stack.popF32();
                const value = v1 / v2;
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Min => {
                try preamble("F32_Min", pc, code, stack);
                const v2 = stack.popF32();
                const v1 = stack.popF32();
                const value = OpHelpers.propagateNanWithOp(.Min, v1, v2);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Max => {
                try preamble("F32_Max", pc, code, stack);
                const v2 = stack.popF32();
                const v1 = stack.popF32();
                const value = OpHelpers.propagateNanWithOp(.Max, v1, v2);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Copysign => {
                try preamble("F32_Copysign", pc, code, stack);
                const v2 = stack.popF32();
                const v1 = stack.popF32();
                const value = std.math.copysign(v1, v2);
                stack.pushF32(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Abs => {
                try preamble("F64_Abs", pc, code, stack);
                const f = stack.popF64();
                const value = @abs(f);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Neg => {
                try preamble("F64_Neg", pc, code, stack);
                const f = stack.popF64();
                stack.pushF64(-f);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Ceil => {
                try preamble("F64_Ceil", pc, code, stack);
                const f = stack.popF64();
                const value = @ceil(f);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Floor => {
                try preamble("F64_Floor", pc, code, stack);
                const f = stack.popF64();
                const value = @floor(f);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Trunc => {
                try preamble("F64_Trunc", pc, code, stack);
                const f = stack.popF64();
                const value = @trunc(f);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Nearest => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Sqrt => {
                try preamble("F64_Sqrt", pc, code, stack);
                const f = stack.popF64();
                const value = std.math.sqrt(f);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Add => {
                try preamble("F64_Add", pc, code, stack);
                const v2 = stack.popF64();
                const v1 = stack.popF64();
                const value = v1 + v2;
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Sub => {
                try preamble("F64_Sub", pc, code, stack);
                const v2 = stack.popF64();
                const v1 = stack.popF64();
                const value = v1 - v2;
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Mul => {
                try preamble("F64_Mul", pc, code, stack);
                const v2 = stack.popF64();
                const v1 = stack.popF64();
                const value = v1 * v2;
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Div => {
                try preamble("F64_Div", pc, code, stack);
                const v2 = stack.popF64();
                const v1 = stack.popF64();
                const value = v1 / v2;
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Min => {
                try preamble("F64_Min", pc, code, stack);
                const v2 = stack.popF64();
                const v1 = stack.popF64();
                const value = OpHelpers.propagateNanWithOp(.Min, v1, v2);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Max => {
                try preamble("F64_Max", pc, code, stack);
                const v2 = stack.popF64();
                const v1 = stack.popF64();
                const value = OpHelpers.propagateNanWithOp(.Max, v1, v2);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Copysign => {
                try preamble("F64_Copysign", pc, code, stack);
                const v2 = stack.popF64();
                const v1 = stack.popF64();
                const value = std.math.copysign(v1, v2);
                stack.pushF64(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Wrap_I64 => {
                try preamble("I32_Wrap_I64", pc, code, stack);
                const v = stack.popI64();
                const mod = @as(i32, @truncate(v));
                stack.pushI32(mod);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_F32_S => {
                try preamble("I32_Trunc_F32_S", pc, code, stack);
                const v = stack.popF32();
                const int = try OpHelpers.truncateTo(i32, v);
                stack.pushI32(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_F32_U => {
                try preamble("I32_Trunc_F32_U", pc, code, stack);
                const v = stack.popF32();
                const int = try OpHelpers.truncateTo(u32, v);
                stack.pushI32(@as(i32, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_F64_S => {
                try preamble("I32_Trunc_F64_S", pc, code, stack);
                const v = stack.popF64();
                const int = try OpHelpers.truncateTo(i32, v);
                stack.pushI32(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_F64_U => {
                try preamble("I32_Trunc_F64_U", pc, code, stack);
                const v = stack.popF64();
                const int = try OpHelpers.truncateTo(u32, v);
                stack.pushI32(@as(i32, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Extend_I32_S => {
                try preamble("I64_Extend_I32_S", pc, code, stack);
                const v32 = stack.popI32();
                const v64: i64 = v32;
                stack.pushI64(v64);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Extend_I32_U => {
                try preamble("I64_Extend_I32_U", pc, code, stack);
                const v32 = stack.popI32();
                const v64: u64 = @as(u32, @bitCast(v32));
                stack.pushI64(@as(i64, @bitCast(v64)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_F32_S => {
                try preamble("I64_Trunc_F32_S", pc, code, stack);
                const v = stack.popF32();
                const int = try OpHelpers.truncateTo(i64, v);
                stack.pushI64(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_F32_U => {
                try preamble("I64_Trunc_F32_U", pc, code, stack);
                const v = stack.popF32();
                const int = try OpHelpers.truncateTo(u64, v);
                stack.pushI64(@as(i64, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_F64_S => {
                try preamble("I64_Trunc_F64_S", pc, code, stack);
                const v = stack.popF64();
                const int = try OpHelpers.truncateTo(i64, v);
                stack.pushI64(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_F64_U => {
                try preamble("I64_Trunc_F64_U", pc, code, stack);
                const v = stack.popF64();
                const int = try OpHelpers.truncateTo(u64, v);
                stack.pushI64(@as(i64, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Convert_I32_S => {
                try preamble("F32_Convert_I32_S", pc, code, stack);
                const v = stack.popI32();
                stack.pushF32(@as(f32, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Convert_I32_U => {
                try preamble("F32_Convert_I32_U", pc, code, stack);
                const v = @as(u32, @bitCast(stack.popI32()));
                stack.pushF32(@as(f32, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Convert_I64_S => {
                try preamble("F32_Convert_I64_S", pc, code, stack);
                const v = stack.popI64();
                stack.pushF32(@as(f32, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Convert_I64_U => {
                try preamble("F32_Convert_I64_U", pc, code, stack);
                const v = @as(u64, @bitCast(stack.popI64()));
                stack.pushF32(@as(f32, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Demote_F64 => {
                try preamble("F32_Demote_F64", pc, code, stack);
                const v = stack.popF64();
                stack.pushF32(@as(f32, @floatCast(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Convert_I32_S => {
                try preamble("F64_Convert_I32_S", pc, code, stack);
                const v = stack.popI32();
                stack.pushF64(@as(f64, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Convert_I32_U => {
                try preamble("F64_Convert_I32_U", pc, code, stack);
                const v = @as(u32, @bitCast(stack.popI32()));
                stack.pushF64(@as(f64, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Convert_I64_S => {
                try preamble("F64_Convert_I64_S", pc, code, stack);
                const v = stack.popI64();
                stack.pushF64(@as(f64, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Convert_I64_U => {
                try preamble("F64_Convert_I64_U", pc, code, stack);
                const v = @as(u64, @bitCast(stack.popI64()));
                stack.pushF64(@as(f64, @floatFromInt(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Promote_F32 => {
                try preamble("F64_Promote_F32", pc, code, stack);
                const v = stack.popF32();
                stack.pushF64(@as(f64, @floatCast(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Reinterpret_F32 => {
                try preamble("I32_Reinterpret_F32", pc, code, stack);
                const v = stack.popF32();
                stack.pushI32(@as(i32, @bitCast(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Reinterpret_F64 => {
                try preamble("I64_Reinterpret_F64", pc, code, stack);
                const v = stack.popF64();
                stack.pushI64(@as(i64, @bitCast(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32_Reinterpret_I32 => {
                try preamble("F32_Reinterpret_I32", pc, code, stack);
                const v = stack.popI32();
                stack.pushF32(@as(f32, @bitCast(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64_Reinterpret_I64 => {
                try preamble("F64_Reinterpret_I64", pc, code, stack);
                const v = stack.popI64();
                stack.pushF64(@as(f64, @bitCast(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Extend8_S => {
                try preamble("I32_Extend8_S", pc, code, stack);
                const v = stack.popI32();
                const v_truncated = @as(i8, @truncate(v));
                const v_extended: i32 = v_truncated;
                stack.pushI32(v_extended);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Extend16_S => {
                try preamble("I32_Extend16_S", pc, code, stack);
                const v = stack.popI32();
                const v_truncated = @as(i16, @truncate(v));
                const v_extended: i32 = v_truncated;
                stack.pushI32(v_extended);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Extend8_S => {
                try preamble("I64_Extend8_S", pc, code, stack);
                const v = stack.popI64();
                const v_truncated = @as(i8, @truncate(v));
                const v_extended: i64 = v_truncated;
                stack.pushI64(v_extended);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Extend16_S => {
                try preamble("I64_Extend16_S", pc, code, stack);
                const v = stack.popI64();
                const v_truncated = @as(i16, @truncate(v));
                const v_extended: i64 = v_truncated;
                stack.pushI64(v_extended);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Extend32_S => {
                try preamble("I64_Extend32_S", pc, code, stack);
                const v = stack.popI64();
                const v_truncated = @as(i32, @truncate(v));
                const v_extended: i64 = v_truncated;
                stack.pushI64(v_extended);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Ref_Null => {
                try preamble("Ref_Null", pc, code, stack);
                const valtype = code[pc].immediate.ValType;
                const val = try Val.nullRef(valtype);
                stack.pushValue(val);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Ref_Is_Null => {
                try preamble("Ref_Is_Null", pc, code, stack);
                const val: Val = stack.popValue();
                const boolean: i32 = if (val.isNull()) 1 else 0;
                stack.pushI32(boolean);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Ref_Func => {
                try preamble("Ref_Func", pc, code, stack);
                const func_index: u32 = code[pc].immediate.Index;
                const val = Val{ .FuncRef = .{ .index = func_index, .module_instance = stack.topFrame().module_instance } };
                stack.pushValue(val);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_Sat_F32_S => {
                try preamble("I32_Trunc_Sat_F32_S", pc, code, stack);
                const v = stack.popF32();
                const int = OpHelpers.saturatedTruncateTo(i32, v);
                stack.pushI32(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_Sat_F32_U => {
                try preamble("I32_Trunc_Sat_F32_U", pc, code, stack);
                const v = stack.popF32();
                const int = OpHelpers.saturatedTruncateTo(u32, v);
                stack.pushI32(@as(i32, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_Sat_F64_S => {
                try preamble("I32_Trunc_Sat_F64_S", pc, code, stack);
                const v = stack.popF64();
                const int = OpHelpers.saturatedTruncateTo(i32, v);
                stack.pushI32(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32_Trunc_Sat_F64_U => {
                try preamble("I32_Trunc_Sat_F64_U", pc, code, stack);
                const v = stack.popF64();
                const int = OpHelpers.saturatedTruncateTo(u32, v);
                stack.pushI32(@as(i32, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_Sat_F32_S => {
                try preamble("I64_Trunc_Sat_F32_S", pc, code, stack);
                const v = stack.popF32();
                const int = OpHelpers.saturatedTruncateTo(i64, v);
                stack.pushI64(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_Sat_F32_U => {
                try preamble("I64_Trunc_Sat_F32_U", pc, code, stack);
                const v = stack.popF32();
                const int = OpHelpers.saturatedTruncateTo(u64, v);
                stack.pushI64(@as(i64, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_Sat_F64_S => {
                try preamble("I64_Trunc_Sat_F64_S", pc, code, stack);
                const v = stack.popF64();
                const int = OpHelpers.saturatedTruncateTo(i64, v);
                stack.pushI64(int);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64_Trunc_Sat_F64_U => {
                try preamble("I64_Trunc_Sat_F64_U", pc, code, stack);
                const v = stack.popF64();
                const int = OpHelpers.saturatedTruncateTo(u64, v);
                stack.pushI64(@as(i64, @bitCast(int)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Memory_Init => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Data_Drop => {
                try preamble("Data_Drop", pc, code, stack);
                const data_index: u32 = code[pc].immediate.Index;
                const data: *DataDefinition = &stack.topFrame().module_instance.module_def.datas.items[data_index];
                data.bytes.clearAndFree();
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Memory_Copy => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Memory_Fill => {
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

                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Table_Init => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Elem_Drop => {
                try preamble("Elem_Drop", pc, code, stack);
                const elem_index: u32 = code[pc].immediate.Index;
                var elem: *ElementInstance = &stack.topFrame().module_instance.store.elements.items[elem_index];
                elem.refs.clearAndFree();
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Table_Copy => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Table_Grow => {
                try preamble("Table_Grow", pc, code, stack);
                const table_index: u32 = code[pc].immediate.Index;
                const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
                const length = @as(u32, @bitCast(stack.popI32()));
                const init_value = stack.popValue();
                const old_length = @as(i32, @intCast(table.refs.items.len));
                const return_value: i32 = if (table.grow(length, init_value)) old_length else -1;
                stack.pushI32(return_value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Table_Size => {
                try preamble("Table_Size", pc, code, stack);
                const table_index: u32 = code[pc].immediate.Index;
                const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
                const length = @as(i32, @intCast(table.refs.items.len));
                stack.pushI32(length);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.Table_Fill => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load => {
                try preamble("V128_Load", pc, code, stack);
                const value = try OpHelpers.loadFromMem(v128, stack, code[pc].immediate.MemoryOffset);
                stack.pushV128(value);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load8x8_S => {
                try preamble("V128_Load8x8_S", pc, code, stack);
                try OpHelpers.vectorLoadExtend(i8, i16, 8, code[pc].immediate.MemoryOffset, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load8x8_U => {
                try preamble("V128_Load8x8_S", pc, code, stack);
                try OpHelpers.vectorLoadExtend(u8, i16, 8, code[pc].immediate.MemoryOffset, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load16x4_S => {
                try preamble("V128_Load16x4_S", pc, code, stack);
                try OpHelpers.vectorLoadExtend(i16, i32, 4, code[pc].immediate.MemoryOffset, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load16x4_U => {
                try preamble("V128_Load16x4_U", pc, code, stack);
                try OpHelpers.vectorLoadExtend(u16, i32, 4, code[pc].immediate.MemoryOffset, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load32x2_S => {
                try preamble("V128_Load32x2_S", pc, code, stack);
                try OpHelpers.vectorLoadExtend(i32, i64, 2, code[pc].immediate.MemoryOffset, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load32x2_U => {
                try preamble("V128_Load32x2_U", pc, code, stack);
                try OpHelpers.vectorLoadExtend(u32, i64, 2, code[pc].immediate.MemoryOffset, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load8_Splat => {
                try preamble("V128_Load8_Splat", pc, code, stack);
                const scalar = try OpHelpers.loadFromMem(u8, stack, code[pc].immediate.MemoryOffset);
                const vec: u8x16 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load16_Splat => {
                try preamble("V128_Load16_Splat", pc, code, stack);
                const scalar = try OpHelpers.loadFromMem(u16, stack, code[pc].immediate.MemoryOffset);
                const vec: u16x8 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load32_Splat => {
                try preamble("V128_Load32_Splat", pc, code, stack);
                const scalar = try OpHelpers.loadFromMem(u32, stack, code[pc].immediate.MemoryOffset);
                const vec: u32x4 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load64_Splat => {
                try preamble("V128_Load64_Splat", pc, code, stack);
                const scalar = try OpHelpers.loadFromMem(u64, stack, code[pc].immediate.MemoryOffset);
                const vec: u64x2 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Splat => {
                try preamble("I8x16_Splat", pc, code, stack);
                const scalar = @as(i8, @truncate(stack.popI32()));
                const vec: i8x16 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Splat => {
                try preamble("I16x8_Splat", pc, code, stack);
                const scalar = @as(i16, @truncate(stack.popI32()));
                const vec: i16x8 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Splat => {
                try preamble("I32x4_Splat", pc, code, stack);
                const scalar = stack.popI32();
                const vec: i32x4 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Splat => {
                try preamble("I64x2_Splat", pc, code, stack);
                const scalar = stack.popI64();
                const vec: i64x2 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Splat => {
                try preamble("F32x4_Splat", pc, code, stack);
                const scalar = stack.popF32();
                const vec: f32x4 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Splat => {
                try preamble("F64x2_Splat", pc, code, stack);
                const scalar = stack.popF64();
                const vec: f64x2 = @splat(scalar);
                stack.pushV128(@as(v128, @bitCast(vec)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Extract_Lane_S => {
                try preamble("I8x16_Extract_Lane_S", pc, code, stack);
                OpHelpers.vectorExtractLane(i8x16, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Extract_Lane_U => {
                try preamble("I8x16_Extract_Lane_U", pc, code, stack);
                OpHelpers.vectorExtractLane(u8x16, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Replace_Lane => {
                try preamble("I8x16_Replace_Lane", pc, code, stack);
                OpHelpers.vectorReplaceLane(i8x16, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extract_Lane_S => {
                try preamble("I16x8_Extract_Lane_S", pc, code, stack);
                OpHelpers.vectorExtractLane(i16x8, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extract_Lane_U => {
                try preamble("I16x8_Extract_Lane_U", pc, code, stack);
                OpHelpers.vectorExtractLane(u16x8, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Replace_Lane => {
                try preamble("I16x8_Replace_Lane", pc, code, stack);
                OpHelpers.vectorReplaceLane(i16x8, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extract_Lane => {
                try preamble("I32x4_Extract_Lane", pc, code, stack);
                OpHelpers.vectorExtractLane(i32x4, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Replace_Lane => {
                try preamble("I32x4_Replace_Lane", pc, code, stack);
                OpHelpers.vectorReplaceLane(i32x4, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Extract_Lane => {
                try preamble("I64x2_Extract_Lane", pc, code, stack);
                OpHelpers.vectorExtractLane(i64x2, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Replace_Lane => {
                try preamble("I64x2_Replace_Lane", pc, code, stack);
                OpHelpers.vectorReplaceLane(i64x2, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Extract_Lane => {
                try preamble("F32x4_Extract_Lane", pc, code, stack);
                OpHelpers.vectorExtractLane(f32x4, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Replace_Lane => {
                try preamble("F32x4_Replace_Lane", pc, code, stack);
                OpHelpers.vectorReplaceLane(f32x4, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Extract_Lane => {
                try preamble("F64x2_Extract_Lane", pc, code, stack);
                OpHelpers.vectorExtractLane(f64x2, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Replace_Lane => {
                try preamble("F64x2_Replace_Lane", pc, code, stack);
                OpHelpers.vectorReplaceLane(f64x2, code[pc].immediate.Index, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_EQ => {
                try preamble("I8x16_EQ", pc, code, stack);
                OpHelpers.vectorBoolOp(i8x16, .Eq, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_NE => {
                try preamble("I8x16_NE", pc, code, stack);
                OpHelpers.vectorBoolOp(i8x16, .Ne, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_LT_S => {
                try preamble("I8x16_LT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i8x16, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_LT_U => {
                try preamble("I8x16_LT_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u8x16, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_GT_S => {
                try preamble("I8x16_GT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i8x16, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_GT_U => {
                try preamble("I8x16_GT_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u8x16, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_LE_S => {
                try preamble("I8x16_LE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i8x16, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_LE_U => {
                try preamble("I8x16_LE_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u8x16, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_GE_S => {
                try preamble("I8x16_GE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i8x16, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_GE_U => {
                try preamble("I8x16_GE_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u8x16, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_EQ => {
                try preamble("I16x8_EQ", pc, code, stack);
                OpHelpers.vectorBoolOp(i16x8, .Eq, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_NE => {
                try preamble("I16x8_NE", pc, code, stack);
                OpHelpers.vectorBoolOp(i16x8, .Ne, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_LT_S => {
                try preamble("I16x8_LT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i16x8, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_LT_U => {
                try preamble("I16x8_LT_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u16x8, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_GT_S => {
                try preamble("I16x8_GT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i16x8, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_GT_U => {
                try preamble("I16x8_GT_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u16x8, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_LE_S => {
                try preamble("I16x8_LE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i16x8, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_LE_U => {
                try preamble("I16x8_LE_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u16x8, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_GE_S => {
                try preamble("I16x8_GE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i16x8, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_GE_U => {
                try preamble("I16x8_GE_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u16x8, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_EQ => {
                try preamble("I32x4_EQ", pc, code, stack);
                OpHelpers.vectorBoolOp(i32x4, .Eq, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_NE => {
                try preamble("I32x4_NE", pc, code, stack);
                OpHelpers.vectorBoolOp(i32x4, .Ne, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_LT_S => {
                try preamble("I32x4_LT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i32x4, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_LT_U => {
                try preamble("I32x4_LT_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u32x4, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_GT_S => {
                try preamble("I32x4_GT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i32x4, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_GT_U => {
                try preamble("I32x4_GT_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u32x4, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_LE_S => {
                try preamble("I32x4_LE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i32x4, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_LE_U => {
                try preamble("I32x4_LE_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u32x4, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_GE_S => {
                try preamble("I32x4_GE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i32x4, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_GE_U => {
                try preamble("I32x4_GE_U", pc, code, stack);
                OpHelpers.vectorBoolOp(u32x4, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_EQ => {
                try preamble("F32x4_EQ", pc, code, stack);
                OpHelpers.vectorBoolOp(f32x4, .Eq, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_NE => {
                try preamble("F32x4_NE", pc, code, stack);
                OpHelpers.vectorBoolOp(f32x4, .Ne, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_LT => {
                try preamble("F32x4_LT", pc, code, stack);
                OpHelpers.vectorBoolOp(f32x4, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_GT => {
                try preamble("F32x4_GT", pc, code, stack);
                OpHelpers.vectorBoolOp(f32x4, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_LE => {
                try preamble("F32x4_LE", pc, code, stack);
                OpHelpers.vectorBoolOp(f32x4, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_GE => {
                try preamble("F32x4_GE", pc, code, stack);
                OpHelpers.vectorBoolOp(f32x4, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_EQ => {
                try preamble("F64x2_EQ", pc, code, stack);
                OpHelpers.vectorBoolOp(f64x2, .Eq, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_NE => {
                try preamble("F64x2_NE", pc, code, stack);
                OpHelpers.vectorBoolOp(f64x2, .Ne, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_LT => {
                try preamble("F64x2_LT", pc, code, stack);
                OpHelpers.vectorBoolOp(f64x2, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_GT => {
                try preamble("F64x2_GT", pc, code, stack);
                OpHelpers.vectorBoolOp(f64x2, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_LE => {
                try preamble("F64x2_LE", pc, code, stack);
                OpHelpers.vectorBoolOp(f64x2, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_GE => {
                try preamble("F64x2_GE", pc, code, stack);
                OpHelpers.vectorBoolOp(f64x2, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Store => {
                try preamble("V128_Store", pc, code, stack);

                const value: v128 = stack.popV128();
                try OpHelpers.storeInMem(value, stack, code[pc].immediate.MemoryOffset);

                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Const => {
                try preamble("V128_Const", pc, code, stack);
                const v: v128 = code[pc].immediate.ValueVec;
                stack.pushV128(v);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Shuffle => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Swizzle => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Not => {
                try preamble("V128_Not", pc, code, stack);
                const v = @as(i8x16, @bitCast(stack.popV128()));
                const inverted = ~v;
                stack.pushV128(@as(v128, @bitCast(inverted)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_And => {
                try preamble("V128_And", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .And, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_AndNot => {
                try preamble("V128_AndNot", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .AndNot, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Or => {
                try preamble("V128_Or", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .Or, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Xor => {
                try preamble("V128_Xor", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .Xor, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Bitselect => {
                try preamble("V128_Bitselect", pc, code, stack);
                const u1x128 = @Vector(128, u1);
                const c = @as(@Vector(128, bool), @bitCast(stack.popV128()));
                const v2 = @as(u1x128, @bitCast(stack.popV128()));
                const v1 = @as(u1x128, @bitCast(stack.popV128()));
                const v = @select(u1, c, v1, v2);
                stack.pushV128(@as(v128, @bitCast(v)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_AnyTrue => {
                try preamble("V128_AnyTrue", pc, code, stack);
                const v = @as(u128, @bitCast(stack.popV128()));
                const boolean: i32 = if (v != 0) 1 else 0;
                stack.pushI32(boolean);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load8_Lane => {
                try preamble("V128_Load8_Lane", pc, code, stack);
                try OpHelpers.vectorLoadLane(u8x16, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load16_Lane => {
                try preamble("V128_Load16_Lane", pc, code, stack);
                try OpHelpers.vectorLoadLane(u16x8, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load32_Lane => {
                try preamble("V128_Load32_Lane", pc, code, stack);
                try OpHelpers.vectorLoadLane(u32x4, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load64_Lane => {
                try preamble("V128_Load64_Lane", pc, code, stack);
                try OpHelpers.vectorLoadLane(u64x2, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Store8_Lane => {
                try preamble("V128_Store8_Lane", pc, code, stack);
                try OpHelpers.vectorStoreLane(u8x16, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Store16_Lane => {
                try preamble("V128_Store16_Lane", pc, code, stack);
                try OpHelpers.vectorStoreLane(u16x8, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Store32_Lane => {
                try preamble("V128_Store32_Lane", pc, code, stack);
                try OpHelpers.vectorStoreLane(u32x4, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Store64_Lane => {
                try preamble("V128_Store64_Lane", pc, code, stack);
                try OpHelpers.vectorStoreLane(u64x2, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load32_Zero => {
                try preamble("V128_Load32_Zero", pc, code, stack);
                try OpHelpers.vectorLoadLaneZero(u32x4, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.V128_Load64_Zero => {
                try preamble("V128_Load64_Zero", pc, code, stack);
                try OpHelpers.vectorLoadLaneZero(u64x2, code[pc], stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Demote_F64x2_Zero => {
                try preamble("F32x4_Demote_F64x2_Zero", pc, code, stack);
                const vec = @as(f64x2, @bitCast(stack.popV128()));
                var arr: [4]f32 = undefined;
                arr[0] = @as(f32, @floatCast(vec[0]));
                arr[1] = @as(f32, @floatCast(vec[1]));
                arr[2] = 0.0;
                arr[3] = 0.0;
                const demoted: f32x4 = arr;
                stack.pushV128(@as(v128, @bitCast(demoted)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Promote_Low_F32x4 => {
                try preamble("F64x2_Promote_Low_F32x4", pc, code, stack);
                const vec = @as(f32x4, @bitCast(stack.popV128()));
                var arr: [2]f64 = undefined;
                arr[0] = vec[0];
                arr[1] = vec[1];
                const promoted: f64x2 = arr;
                stack.pushV128(@as(v128, @bitCast(promoted)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Abs => {
                try preamble("I8x16_Abs", pc, code, stack);
                OpHelpers.vectorAbs(i8x16, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Neg => {
                try preamble("I8x16_Neg", pc, code, stack);
                const vec = @as(i8x16, @bitCast(stack.popV128()));
                const negated = -%vec;
                stack.pushV128(@as(v128, @bitCast(negated)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Popcnt => {
                try preamble("I8x16_Popcnt", pc, code, stack);
                const vec = @as(i8x16, @bitCast(stack.popV128()));
                const result: u8x16 = @popCount(vec);
                stack.pushV128(@as(v128, @bitCast(@as(v128, @bitCast(result)))));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_AllTrue => {
                try preamble("I8x16_AllTrue", pc, code, stack);
                const boolean = OpHelpers.vectorAllTrue(i8x16, stack.popV128());
                stack.pushI32(boolean);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Bitmask => {
                try preamble("I8x16_Bitmask", pc, code, stack);
                const bitmask: i32 = OpHelpers.vectorBitmask(i8x16, stack.popV128());
                stack.pushI32(bitmask);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Narrow_I16x8_S => {
                try preamble("I8x16_Narrow_I16x8_S", pc, code, stack);
                OpHelpers.vectorNarrow(i16x8, i8x16, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Narrow_I16x8_U => {
                try preamble("I8x16_Narrow_I16x8_U", pc, code, stack);
                OpHelpers.vectorNarrow(i16x8, u8x16, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Ceil => {
                try preamble("F32x4_Ceil", pc, code, stack);
                OpHelpers.vectorUnOp(f32x4, .Ceil, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Floor => {
                try preamble("F32x4_Floor", pc, code, stack);
                OpHelpers.vectorUnOp(f32x4, .Floor, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Trunc => {
                try preamble("F32x4_Trunc", pc, code, stack);
                OpHelpers.vectorUnOp(f32x4, .Trunc, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Nearest => {
                try preamble("F32x4_Nearest", pc, code, stack);
                OpHelpers.vectorUnOp(f32x4, .Nearest, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Shl => {
                try preamble("I8x16_Shl", pc, code, stack);
                OpHelpers.vectorShift(i8x16, .Left, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Shr_S => {
                try preamble("I8x16_Shr_S", pc, code, stack);
                OpHelpers.vectorShift(i8x16, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Shr_U => {
                try preamble("I8x16_Shr_U", pc, code, stack);
                OpHelpers.vectorShift(u8x16, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Add => {
                try preamble("I8x16_Add", pc, code, stack);
                OpHelpers.vectorBinOp(u8x16, .Add, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Add_Sat_S => {
                try preamble("I8x16_Add_Sat_S", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .Add_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Add_Sat_U => {
                try preamble("I8x16_Add_Sat_U", pc, code, stack);
                OpHelpers.vectorBinOp(u8x16, .Add_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Sub => {
                try preamble("I8x16_Sub", pc, code, stack);
                OpHelpers.vectorBinOp(u8x16, .Sub, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Sub_Sat_S => {
                try preamble("I8x16_Sub_Sat_S", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .Sub_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Sub_Sat_U => {
                try preamble("I8x16_Sub_Sat_U", pc, code, stack);
                OpHelpers.vectorBinOp(u8x16, .Sub_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Ceil => {
                try preamble("F64x2_Ceil", pc, code, stack);
                OpHelpers.vectorUnOp(f64x2, .Ceil, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Floor => {
                try preamble("F64x2_Floor", pc, code, stack);
                OpHelpers.vectorUnOp(f64x2, .Floor, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Min_S => {
                try preamble("I8x16_Min_S", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Min_U => {
                try preamble("I8x16_Min_U", pc, code, stack);
                OpHelpers.vectorBinOp(u8x16, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Max_S => {
                try preamble("I8x16_Max_S", pc, code, stack);
                OpHelpers.vectorBinOp(i8x16, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Max_U => {
                try preamble("I8x16_Max_U", pc, code, stack);
                OpHelpers.vectorBinOp(u8x16, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Trunc => {
                try preamble("F64x2_Trunc", pc, code, stack);
                OpHelpers.vectorUnOp(f64x2, .Trunc, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I8x16_Avgr_U => {
                try preamble("I8x16_Avgr_U", pc, code, stack);
                OpHelpers.vectorAvgrU(u8x16, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extadd_Pairwise_I8x16_S => {
                try preamble("I16x8_Extadd_Pairwise_I8x16_S", pc, code, stack);
                OpHelpers.vectorAddPairwise(i8x16, i16x8, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extadd_Pairwise_I8x16_U => {
                try preamble("I16x8_Extadd_Pairwise_I8x16_U", pc, code, stack);
                OpHelpers.vectorAddPairwise(u8x16, u16x8, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extadd_Pairwise_I16x8_S => {
                try preamble("I32x4_Extadd_Pairwise_I16x8_S", pc, code, stack);
                OpHelpers.vectorAddPairwise(i16x8, i32x4, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extadd_Pairwise_I16x8_U => {
                try preamble("I32x4_Extadd_Pairwise_I16x8_U", pc, code, stack);
                OpHelpers.vectorAddPairwise(u16x8, u32x4, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Abs => {
                try preamble("I16x8_Abs", pc, code, stack);
                OpHelpers.vectorAbs(i16x8, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Neg => {
                try preamble("I16x8_Neg", pc, code, stack);
                const vec = @as(u16x8, @bitCast(stack.popV128()));
                const negated = -%vec;
                stack.pushV128(@as(v128, @bitCast(negated)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Q15mulr_Sat_S => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_AllTrue => {
                try preamble("I16x8_AllTrue", pc, code, stack);
                const boolean: i32 = OpHelpers.vectorAllTrue(i16x8, stack.popV128());
                stack.pushI32(boolean);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Bitmask => {
                try preamble("I16x8_Bitmask", pc, code, stack);
                const bitmask: i32 = OpHelpers.vectorBitmask(i16x8, stack.popV128());
                stack.pushI32(bitmask);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Narrow_I32x4_S => {
                try preamble("I16x8_Narrow_I32x4_S", pc, code, stack);
                OpHelpers.vectorNarrow(i32x4, i16x8, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Narrow_I32x4_U => {
                try preamble("I16x8_Narrow_I32x4_U", pc, code, stack);
                OpHelpers.vectorNarrow(i32x4, u16x8, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extend_Low_I8x16_S => {
                try preamble("I16x8_Extend_Low_I8x16_S", pc, code, stack);
                OpHelpers.vectorExtend(i8x16, i16x8, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extend_High_I8x16_S => {
                try preamble("I16x8_Extend_High_I8x16_S", pc, code, stack);
                OpHelpers.vectorExtend(i8x16, i16x8, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extend_Low_I8x16_U => {
                try preamble("I16x8_Extend_Low_I8x16_U", pc, code, stack);
                OpHelpers.vectorExtend(u8x16, i16x8, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
            Opcode.I16x8_Extend_High_I8x16_U => {
                try preamble("I16x8_Extend_High_I8x16_U", pc, code, stack);
                OpHelpers.vectorExtend(u8x16, i16x8, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Shl => {
                try preamble("I16x8_Shl", pc, code, stack);
                OpHelpers.vectorShift(i16x8, .Left, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Shr_S => {
                try preamble("I16x8_Shr_S", pc, code, stack);
                OpHelpers.vectorShift(i16x8, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Shr_U => {
                try preamble("I16x8_Shr_U", pc, code, stack);
                OpHelpers.vectorShift(u16x8, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Add => {
                try preamble("I16x8_Add", pc, code, stack);
                OpHelpers.vectorBinOp(i16x8, .Add, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Add_Sat_S => {
                try preamble("I16x8_Add_Sat_S", pc, code, stack);
                OpHelpers.vectorBinOp(i16x8, .Add_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Add_Sat_U => {
                try preamble("I16x8_Add_Sat_U", pc, code, stack);
                OpHelpers.vectorBinOp(u16x8, .Add_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Sub => {
                try preamble("I16x8_Sub", pc, code, stack);
                OpHelpers.vectorBinOp(i16x8, .Sub, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Sub_Sat_S => {
                try preamble("I16x8_Sub_Sat_S", pc, code, stack);
                OpHelpers.vectorBinOp(i16x8, .Sub_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Sub_Sat_U => {
                try preamble("I16x8_Sub_Sat_U", pc, code, stack);
                OpHelpers.vectorBinOp(u16x8, .Sub_Sat, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Nearest => {
                try preamble("F64x2_Nearest", pc, code, stack);
                OpHelpers.vectorUnOp(f64x2, .Nearest, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Mul => {
                try preamble("I16x8_Mul", pc, code, stack);
                OpHelpers.vectorBinOp(i16x8, .Mul, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Min_S => {
                try preamble("I16x8_Min_S", pc, code, stack);
                OpHelpers.vectorBinOp(i16x8, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Min_U => {
                try preamble("I16x8_Min_U", pc, code, stack);
                OpHelpers.vectorBinOp(u16x8, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Max_S => {
                try preamble("I16x8_Max_S", pc, code, stack);
                OpHelpers.vectorBinOp(i16x8, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Max_U => {
                try preamble("I16x8_Max_U", pc, code, stack);
                OpHelpers.vectorBinOp(u16x8, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Avgr_U => {
                try preamble("I16x8_Avgr_U", pc, code, stack);
                OpHelpers.vectorAvgrU(u16x8, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extmul_Low_I8x16_S => {
                try preamble("I16x8_Extmul_Low_I8x16_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(i8x16, i16x8, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extmul_High_I8x16_S => {
                try preamble("I16x8_Extmul_High_I8x16_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(i8x16, i16x8, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extmul_Low_I8x16_U => {
                try preamble("I16x8_Extmul_Low_I8x16_U", pc, code, stack);
                OpHelpers.vectorMulPairwise(u8x16, u16x8, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I16x8_Extmul_High_I8x16_U => {
                try preamble("I16x8_Extmul_High_I8x16_U", pc, code, stack);
                OpHelpers.vectorMulPairwise(u8x16, u16x8, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Abs => {
                try preamble("I32x4_Abs", pc, code, stack);
                OpHelpers.vectorAbs(i32x4, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Neg => {
                try preamble("I32x4_Neg", pc, code, stack);
                const vec = @as(i32x4, @bitCast(stack.popV128()));
                const negated = -%vec;
                stack.pushV128(@as(v128, @bitCast(negated)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_AllTrue => {
                try preamble("I32x4_AllTrue", pc, code, stack);
                const boolean: i32 = OpHelpers.vectorAllTrue(i32x4, stack.popV128());
                stack.pushI32(boolean);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Bitmask => {
                try preamble("I32x4_Bitmask", pc, code, stack);
                const bitmask: i32 = OpHelpers.vectorBitmask(i32x4, stack.popV128());
                stack.pushI32(bitmask);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extend_Low_I16x8_S => {
                try preamble("I32x4_Extend_Low_I16x8_S", pc, code, stack);
                OpHelpers.vectorExtend(i16x8, i32x4, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extend_High_I16x8_S => {
                try preamble("I32x4_Extend_High_I16x8_S", pc, code, stack);
                OpHelpers.vectorExtend(i16x8, i32x4, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extend_Low_I16x8_U => {
                try preamble("I32x4_Extend_Low_I16x8_U", pc, code, stack);
                OpHelpers.vectorExtend(u16x8, i32x4, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extend_High_I16x8_U => {
                try preamble("I32x4_Extend_High_I16x8_U", pc, code, stack);
                OpHelpers.vectorExtend(u16x8, i32x4, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Shl => {
                try preamble("I32x4_Shl", pc, code, stack);
                OpHelpers.vectorShift(i32x4, .Left, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Shr_S => {
                try preamble("I32x4_Shr_S", pc, code, stack);
                OpHelpers.vectorShift(i32x4, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Shr_U => {
                try preamble("I32x4_Shr_U", pc, code, stack);
                OpHelpers.vectorShift(u32x4, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Abs => {
                try preamble("I64x2_Abs", pc, code, stack);
                OpHelpers.vectorAbs(i64x2, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Neg => {
                try preamble("I64x2_Neg", pc, code, stack);
                const vec = @as(i64x2, @bitCast(stack.popV128()));
                const negated = -%vec;
                stack.pushV128(@as(v128, @bitCast(negated)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_AllTrue => {
                try preamble("I64x2_AllTrue", pc, code, stack);
                const boolean = OpHelpers.vectorAllTrue(i64x2, stack.popV128());
                stack.pushI32(boolean);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Bitmask => {
                try preamble("I64x2_Bitmask", pc, code, stack);
                const bitmask: i32 = OpHelpers.vectorBitmask(i64x2, stack.popV128());
                stack.pushI32(bitmask);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Extend_Low_I32x4_S => {
                try preamble("I64x2_Extend_Low_I32x4_S", pc, code, stack);
                OpHelpers.vectorExtend(i32x4, i64x2, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Extend_High_I32x4_S => {
                try preamble("I64x2_Extend_High_I32x4_S", pc, code, stack);
                OpHelpers.vectorExtend(i32x4, i64x2, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Extend_Low_I32x4_U => {
                try preamble("I64x2_Extend_Low_I32x4_U", pc, code, stack);
                OpHelpers.vectorExtend(u32x4, i64x2, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Extend_High_I32x4_U => {
                try preamble("I64x2_Extend_High_I32x4_U", pc, code, stack);
                OpHelpers.vectorExtend(u32x4, i64x2, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Shl => {
                try preamble("I64x2_Shl", pc, code, stack);
                OpHelpers.vectorShift(i64x2, .Left, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Shr_S => {
                try preamble("I64x2_Shr_S", pc, code, stack);
                OpHelpers.vectorShift(i64x2, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Shr_U => {
                try preamble("I64x2_Shr_U", pc, code, stack);
                OpHelpers.vectorShift(u64x2, .Right, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Add => {
                try preamble("I32x4_Add", pc, code, stack);
                OpHelpers.vectorBinOp(i32x4, .Add, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Sub => {
                try preamble("I32x4_Sub", pc, code, stack);
                OpHelpers.vectorBinOp(i32x4, .Sub, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Mul => {
                try preamble("I32x4_Mul", pc, code, stack);
                OpHelpers.vectorBinOp(i32x4, .Mul, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Min_S => {
                try preamble("I32x4_Min_S", pc, code, stack);
                OpHelpers.vectorBinOp(i32x4, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Min_U => {
                try preamble("I32x4_Min_U", pc, code, stack);
                OpHelpers.vectorBinOp(u32x4, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Max_S => {
                try preamble("I32x4_Max_S", pc, code, stack);
                OpHelpers.vectorBinOp(i32x4, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Max_U => {
                try preamble("I32x4_Max_U", pc, code, stack);
                OpHelpers.vectorBinOp(u32x4, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Dot_I16x8_S => {
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
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extmul_Low_I16x8_S => {
                try preamble("I32x4_Extmul_Low_I16x8_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(i16x8, i32x4, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extmul_High_I16x8_S => {
                try preamble("I32x4_Extmul_High_I16x8_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(i16x8, i32x4, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extmul_Low_I16x8_U => {
                try preamble("I32x4_Extmul_Low_I16x8_U", pc, code, stack);
                OpHelpers.vectorMulPairwise(u16x8, u32x4, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Extmul_High_I16x8_U => {
                try preamble("I32x4_Extmul_High_I16x8_U", pc, code, stack);
                OpHelpers.vectorMulPairwise(u16x8, u32x4, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Add => {
                try preamble("I64x2_Add", pc, code, stack);
                OpHelpers.vectorBinOp(i64x2, .Add, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Sub => {
                try preamble("I64x2_Sub", pc, code, stack);
                OpHelpers.vectorBinOp(i64x2, .Sub, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Mul => {
                try preamble("I64x2_Mul", pc, code, stack);
                OpHelpers.vectorBinOp(i64x2, .Mul, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_EQ => {
                try preamble("I64x2_EQ", pc, code, stack);
                OpHelpers.vectorBoolOp(i64x2, .Eq, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_NE => {
                try preamble("I64x2_NE", pc, code, stack);
                OpHelpers.vectorBoolOp(i64x2, .Ne, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_LT_S => {
                try preamble("I64x2_LT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i64x2, .Lt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_GT_S => {
                try preamble("I64x2_GT_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i64x2, .Gt, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_LE_S => {
                try preamble("I64x2_LE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i64x2, .Le, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_GE_S => {
                try preamble("I64x2_GE_S", pc, code, stack);
                OpHelpers.vectorBoolOp(i64x2, .Ge, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I64x2_Extmul_Low_I32x4_S => {
                try preamble("I64x2_GE_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(i32x4, i64x2, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
            Opcode.I64x2_Extmul_High_I32x4_S => {
                try preamble("I64x2_GE_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(i32x4, i64x2, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
            Opcode.I64x2_Extmul_Low_I32x4_U => {
                try preamble("I64x2_GE_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(u32x4, u64x2, .Low, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
            Opcode.I64x2_Extmul_High_I32x4_U => {
                try preamble("I64x2_GE_S", pc, code, stack);
                OpHelpers.vectorMulPairwise(u32x4, u64x2, .High, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Abs => {
                try preamble("F32x4_Abs", pc, code, stack);
                const vec = @as(f32x4, @bitCast(stack.popV128()));
                const abs = @abs(vec);
                stack.pushV128(@as(v128, @bitCast(abs)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Neg => {
                try preamble("F32x4_Neg", pc, code, stack);
                const vec = @as(f32x4, @bitCast(stack.popV128()));
                const negated = -vec;
                stack.pushV128(@as(v128, @bitCast(negated)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Sqrt => {
                try preamble("F32x4_Sqrt", pc, code, stack);
                const vec = @as(f32x4, @bitCast(stack.popV128()));
                const root = @sqrt(vec);
                stack.pushV128(@as(v128, @bitCast(root)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Add => {
                try preamble("F32x4_Add", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .Add, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Sub => {
                try preamble("F32x4_Sub", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .Sub, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Mul => {
                try preamble("F32x4_Mul", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .Mul, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Div => {
                try preamble("F32x4_Div", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .Div, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Min => {
                try preamble("F32x4_Min", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Max => {
                try preamble("F32x4_Max", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_PMin => {
                try preamble("F32x4_PMin", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .PMin, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_PMax => {
                try preamble("F32x4_PMax", pc, code, stack);
                OpHelpers.vectorBinOp(f32x4, .PMax, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Abs => {
                try preamble("F64x2_Abs", pc, code, stack);
                const vec = @as(f64x2, @bitCast(stack.popV128()));
                const abs = @abs(vec);
                stack.pushV128(@as(v128, @bitCast(abs)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Neg => {
                try preamble("F64x2_Neg", pc, code, stack);
                const vec = @as(f64x2, @bitCast(stack.popV128()));
                const negated = -vec;
                stack.pushV128(@as(v128, @bitCast(negated)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Sqrt => {
                try preamble("F64x2_Sqrt", pc, code, stack);
                const vec = @as(f64x2, @bitCast(stack.popV128()));
                const root = @sqrt(vec);
                stack.pushV128(@as(v128, @bitCast(root)));
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Add => {
                try preamble("F64x2_Add", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .Add, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Sub => {
                try preamble("F64x2_Sub", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .Sub, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Mul => {
                try preamble("F64x2_Mul", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .Mul, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Div => {
                try preamble("F64x2_Div", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .Div, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Min => {
                try preamble("F64x2_Min", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .Min, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Max => {
                try preamble("F64x2_Max", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .Max, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_PMin => {
                try preamble("F64x2_PMin", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .PMin, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_PMax => {
                try preamble("F64x2_PMax", pc, code, stack);
                OpHelpers.vectorBinOp(f64x2, .PMax, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Trunc_Sat_F32x4_S => {
                try preamble("F32x4_Trunc_Sat_F32x4_S", pc, code, stack);
                OpHelpers.vectorConvert(f32x4, i32x4, .Low, .Saturate, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Trunc_Sat_F32x4_U => {
                try preamble("F32x4_Trunc_Sat_F32x4_U", pc, code, stack);
                OpHelpers.vectorConvert(f32x4, u32x4, .Low, .Saturate, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Convert_I32x4_S => {
                try preamble("F32x4_Convert_I32x4_S", pc, code, stack);
                OpHelpers.vectorConvert(i32x4, f32x4, .Low, .SafeCast, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F32x4_Convert_I32x4_U => {
                try preamble("F32x4_Convert_I32x4_U", pc, code, stack);
                OpHelpers.vectorConvert(u32x4, f32x4, .Low, .SafeCast, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Trunc_Sat_F64x2_S_Zero => {
                try preamble("I32x4_Trunc_Sat_F64x2_S_Zero", pc, code, stack);
                OpHelpers.vectorConvert(f64x2, i32x4, .Low, .Saturate, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.I32x4_Trunc_Sat_F64x2_U_Zero => {
                try preamble("I32x4_Trunc_Sat_F64x2_U_Zero", pc, code, stack);
                OpHelpers.vectorConvert(f64x2, u32x4, .Low, .Saturate, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Convert_Low_I32x4_S => {
                try preamble("F64x2_Convert_Low_I32x4_S", pc, code, stack);
                OpHelpers.vectorConvert(i32x4, f64x2, .Low, .SafeCast, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },

            Opcode.F64x2_Convert_Low_I32x4_U => {
                try preamble("F64x2_Convert_Low_I32x4_U", pc, code, stack);
                OpHelpers.vectorConvert(u32x4, f64x2, .Low, .SafeCast, stack);
                pc += 1;
                continue :interpret code[pc].opcode;
            },
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
