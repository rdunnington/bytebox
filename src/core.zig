const std = @import("std");
const builtin = @import("builtin");
const StableArray = @import("zig-stable-array/stable_array.zig").StableArray;

const opcodes = @import("opcode.zig");
const Opcode = opcodes.Opcode;
const WasmOpcode = opcodes.WasmOpcode;

pub const MalformedError = error{
    MalformedMagicSignature,
    MalformedUnexpectedEnd,
    MalformedUnsupportedWasmVersion,
    MalformedSectionId,
    MalformedTypeSentinel,
    MalformedLEB128,
    MalformedMissingZeroByte,
    MalformedTooManyLocals,
    MalformedFunctionCodeSectionMismatch,
    MalformedMissingDataCountSection,
    MalformedDataCountMismatch,
    MalformedDataType,
    MalformedIllegalOpcode,
    MalformedReferenceType,
    MalformedSectionSizeMismatch,
    MalformedInvalidImport,
    MalformedLimits,
    MalformedMultipleStartSections,
    MalformedElementType,
    MalformedUTF8Encoding,
    MalformedMutability,
};

pub const UnlinkableError = error{
    UnlinkableUnknownImport,
    UnlinkableIncompatibleImportType,
};

pub const UninstantiableError = error{
    UninstantiableOutOfBoundsTableAccess,
    UninstantiableOutOfBoundsMemoryAccess,
};

// todo remove these?
pub const AssertError = error{
    AssertInvalidValType,
    AssertInvalidBytecode,
    AssertInvalidExport,
    AssertInvalidLabel,
    AssertInvalidElement,
    AssertTableMaxExceeded,
    AssertUnknownTable,
    AssertUnknownType,
    AssertIncompleteInstruction,
    AssertUnknownInstruction,
    AssertUnknownExport,
    AssertMissingCallFrame,
    AssertInvalidFunction,

    ModuleAlreadyDecoded,
    ModuleAlreadyInstantiated,
};

pub const ValidationError = error{
    ValidationTypeMismatch,
    ValidationTypeMustBeNumeric,
    ValidationUnknownType,
    ValidationUnknownFunction,
    ValidationUnknownGlobal,
    ValidationUnknownLocal,
    ValidationUnknownTable,
    ValidationUnknownMemory,
    ValidationUnknownElement,
    ValidationUnknownData,
    ValidationOutOfBounds,
    ValidationTypeStackHeightMismatch,
    ValidationBadAlignment,
    ValidationUnknownLabel,
    ValidationImmutableGlobal,
    ValidationBadConstantExpression,
    ValidationGlobalReferencingMutableGlobal,
    ValidationUnknownBlockTypeIndex,
    ValidationSelectArity,
    ValidationMultipleMemories,
    ValidationMemoryInvalidMaxLimit,
    ValidationMemoryMaxPagesExceeded,
    ValidationConstantExpressionGlobalMustBeImport,
    ValidationConstantExpressionGlobalMustBeImmutable,
    ValidationStartFunctionType,
    ValidationLimitsMinMustNotBeLargerThanMax,
    ValidationConstantExpressionTypeMismatch,
    ValidationDuplicateExportName,
    ValidationFuncRefUndeclared,
    ValidationIfElseMismatch,
};

pub const TrapError = error{
    TrapUnreachable,
    TrapIntegerDivisionByZero,
    TrapIntegerOverflow,
    TrapIndirectCallTypeMismatch,
    TrapInvalidIntegerConversion,
    TrapOutOfBoundsMemoryAccess,
    TrapUndefinedElement,
    TrapUninitializedElement,
    TrapOutOfBoundsTableAccess,
    TrapStackExhausted,
    TrapUnknown,
};

pub const WasmError = MalformedError || ValidationError || UnlinkableError || UninstantiableError || AssertError || TrapError;

const ScratchAllocator = struct {
    buffer: StableArray(u8),

    const InitOpts = struct {
        max_size: usize,
    };

    fn init(opts: InitOpts) ScratchAllocator {
        return ScratchAllocator{
            .buffer = StableArray(u8).init(opts.max_size),
        };
    }

    fn allocator(self: *ScratchAllocator) std.mem.Allocator {
        return std.mem.Allocator.init(self, alloc, resize, free);
    }

    pub fn reset(self: *ScratchAllocator) void {
        self.buffer.resize(0) catch unreachable;
    }

    fn alloc(
        self: *ScratchAllocator,
        len: usize,
        ptr_align: u29,
        len_align: u29,
        ret_addr: usize,
    ) std.mem.Allocator.Error![]u8 {
        _ = ret_addr;
        _ = len_align;

        const alloc_size = len;
        const offset_begin = std.mem.alignForward(self.buffer.items.len, ptr_align);
        const offset_end = offset_begin + alloc_size;
        self.buffer.resize(offset_end) catch {
            return std.mem.Allocator.Error.OutOfMemory;
        };
        return self.buffer.items[offset_begin..offset_end];
    }

    fn resize(
        self: *ScratchAllocator,
        old_mem: []u8,
        old_align: u29,
        new_size: usize,
        len_align: u29,
        ret_addr: usize,
    ) ?usize {
        _ = self;
        _ = old_align;
        _ = ret_addr;

        if (new_size > old_mem.len) {
            return null;
        }
        const aligned_size: usize = if (len_align == 0) new_size else std.mem.alignForward(new_size, len_align);
        return aligned_size;
    }

    fn free(
        self: *ScratchAllocator,
        old_mem: []u8,
        old_align: u29,
        ret_addr: usize,
    ) void {
        _ = self;
        _ = old_mem;
        _ = old_align;
        _ = ret_addr;
    }
};

pub const ValType = enum(u8) {
    I32,
    I64,
    F32,
    F64,
    FuncRef,
    ExternRef,

    fn bytecodeToValtype(byte: u8) !ValType {
        return switch (byte) {
            0x7F => .I32,
            0x7E => .I64,
            0x7D => .F32,
            0x7C => .F64,
            0x70 => .FuncRef,
            0x6F => .ExternRef,
            else => {
                return error.AssertInvalidValType;
            },
        };
    }

    fn decode(reader: anytype) !ValType {
        return try bytecodeToValtype(try reader.readByte());
    }

    fn decodeReftype(reader: anytype) !ValType {
        var valtype = try decode(reader);
        if (isRefType(valtype) == false) {
            return error.MalformedReferenceType;
        }
        return valtype;
    }

    fn isRefType(valtype: ValType) bool {
        return switch (valtype) {
            .FuncRef => true,
            .ExternRef => true,
            else => false,
        };
    }

    fn count() comptime_int {
        return @typeInfo(ValType).Enum.fields.len;
    }
};

// Empty instances of these help avoid nullable pointers. Nullable pointers make structs bigger which
// fights cache coherency.
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var empty_module_definition = ModuleDefinition.init(gpa.allocator());
var empty_module_instance = ModuleInstance.init(&empty_module_definition, gpa.allocator());

pub const Val = union(ValType) {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
    FuncRef: struct {
        module_instance: *ModuleInstance,
        index: u32, // index into functions
    },
    ExternRef: u32, // TODO figure out what this indexes

    const k_null_funcref: u32 = std.math.maxInt(u32);

    fn default(valtype: ValType) Val {
        return switch (valtype) {
            .I32 => Val{ .I32 = 0 },
            .I64 => Val{ .I64 = 0 },
            .F32 => Val{ .F32 = 0.0 },
            .F64 => Val{ .F64 = 0.0 },
            .FuncRef => nullRef(.FuncRef) catch unreachable,
            .ExternRef => nullRef(.ExternRef) catch unreachable,
        };
    }

    pub fn nullRef(valtype: ValType) !Val {
        return switch (valtype) {
            .FuncRef => funcrefFromIndex(Val.k_null_funcref),
            .ExternRef => Val{ .ExternRef = Val.k_null_funcref },
            else => error.AssertInvalidBytecode,
        };
    }

    pub fn funcrefFromIndex(index: u32) Val {
        return Val{ .FuncRef = .{ .index = index, .module_instance = &empty_module_instance } };
    }

    fn get(val: Val, comptime T: type) !T {
        switch (T) {
            i32 => if (std.meta.activeTag(val) == .I32) {
                return val.I32;
            },
            u32 => if (std.meta.activeTag(val) == .I32) {
                return @bitCast(u32, val.I32);
            },
            i64 => if (std.meta.activeTag(val) == .I64) {
                return val.I64;
            },
            u64 => if (std.meta.activeTag(val) == .I64) {
                return @bitCast(u64, val.I64);
            },
            f32 => if (std.meta.activeTag(val) == .F32) {
                return val.F64;
            },
            f64 => if (std.meta.activeTag(val) == .F64) {
                return val.F64;
            },
            else => unreachable,
        }

        return error.ValidationTypeMismatch;
    }

    fn isRefType(v: Val) bool {
        return switch (v) {
            .FuncRef => true,
            .ExternRef => true,
            else => false,
        };
    }

    fn isNull(v: Val) bool {
        return switch (v) {
            .FuncRef => |s| s.index == k_null_funcref,
            .ExternRef => |index| index == k_null_funcref,
            else => {
                unreachable;
            },
        };
    }
};

const BlockType = enum {
    Void,
    ValType,
    TypeIndex,
};

const BlockTypeValue = union(BlockType) {
    Void: void,
    ValType: ValType,
    TypeIndex: u32,

    fn getBlocktypeParamTypes(blocktype: BlockTypeValue, module_def: *const ModuleDefinition) []const ValType {
        switch (blocktype) {
            else => return &BlockTypeStatics.empty,
            .TypeIndex => |index| return module_def.types.items[index].getParams(),
        }
    }

    fn getBlocktypeReturnTypes(blocktype: BlockTypeValue, module_def: *const ModuleDefinition) []const ValType {
        switch (blocktype) {
            .Void => return &BlockTypeStatics.empty,
            .ValType => |v| return switch (v) {
                .I32 => &BlockTypeStatics.valtype_i32,
                .I64 => &BlockTypeStatics.valtype_i64,
                .F32 => &BlockTypeStatics.valtype_f32,
                .F64 => &BlockTypeStatics.valtype_f64,
                .FuncRef => &BlockTypeStatics.reftype_funcref,
                .ExternRef => &BlockTypeStatics.reftype_externref,
            },
            .TypeIndex => |index| return module_def.types.items[index].getReturns(),
        }
    }

    fn toU64(value: BlockTypeValue) u64 {
        comptime {
            std.debug.assert(@sizeOf(BlockTypeValue) == @sizeOf(u64));
        }
        const value_ptr: *const BlockTypeValue = &value;
        return @ptrCast(*const u64, @alignCast(8, value_ptr)).*;
    }

    fn fromU64(value: u64) BlockTypeValue {
        const value_ptr: *const u64 = &value;
        return @ptrCast(*const BlockTypeValue, @alignCast(4, value_ptr)).*;
    }
};

const BlockTypeStatics = struct {
    const empty = [_]ValType{};
    const valtype_i32 = [_]ValType{.I32};
    const valtype_i64 = [_]ValType{.I64};
    const valtype_f32 = [_]ValType{.F32};
    const valtype_f64 = [_]ValType{.F64};
    const reftype_funcref = [_]ValType{.FuncRef};
    const reftype_externref = [_]ValType{.ExternRef};
};

const Label = struct {
    num_returns: u32,
    continuation: u32,
    start_offset_values: u32,
};

const CallFrame = struct {
    func: *const FunctionInstance,
    module_instance: *ModuleInstance,
    locals: []Val,
    start_offset_values: u32,
    start_offset_labels: u16,
};

const FuncCallData = struct {
    code: [*]const Instruction,
    continuation: u32,
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

    const Self = @This();

    const AllocOpts = struct {
        max_values: u32,
        max_labels: u16,
        max_frames: u16,
    };

    fn init(allocator: std.mem.Allocator) Self {
        var self = Self{
            .values = &[_]Val{},
            .labels = &[_]Label{},
            .frames = &[_]CallFrame{},
            .num_values = 0,
            .num_labels = 0,
            .num_frames = 0,
            .mem = &[_]u8{},
            .allocator = allocator,
        };

        return self;
    }

    fn deinit(self: *Self) void {
        self.allocator.free(self.mem);
    }

    fn allocMemory(self: *Self, opts: AllocOpts) !void {
        const alignment = std.math.max3(@alignOf(Val), @alignOf(Label), @alignOf(CallFrame));
        const values_alloc_size = std.mem.alignForward(@intCast(usize, opts.max_values) * @sizeOf(Val), alignment);
        const labels_alloc_size = std.mem.alignForward(@intCast(usize, opts.max_labels) * @sizeOf(Label), alignment);
        const frames_alloc_size = std.mem.alignForward(@intCast(usize, opts.max_frames) * @sizeOf(CallFrame), alignment);
        const total_alloc_size: usize = values_alloc_size + labels_alloc_size + frames_alloc_size;

        const begin_labels = values_alloc_size;
        const begin_frames = values_alloc_size + labels_alloc_size;

        self.mem = try self.allocator.alloc(u8, total_alloc_size);
        self.values.ptr = @ptrCast([*]Val, @alignCast(@alignOf(Val), self.mem.ptr));
        self.values.len = opts.max_values;
        self.labels.ptr = @ptrCast([*]Label, @alignCast(@alignOf(Label), self.mem[begin_labels..].ptr));
        self.labels.len = opts.max_labels;
        self.frames.ptr = @ptrCast([*]CallFrame, @alignCast(@alignOf(CallFrame), self.mem[begin_frames..].ptr));
        self.frames.len = opts.max_frames;
    }

    fn pushValue(self: *Self, value: Val) !void {
        if (self.num_values < self.values.len) {
            self.values[self.num_values] = value;
            self.num_values += 1;
        } else {
            return error.TrapStackExhausted;
        }
    }

    fn pushI32(self: *Self, v: i32) !void {
        var typed = Val{ .I32 = v };
        try self.pushValue(typed);
    }

    fn pushI64(self: *Self, v: i64) !void {
        var typed = Val{ .I64 = v };
        try self.pushValue(typed);
    }

    fn pushF32(self: *Self, v: f32) !void {
        var typed = Val{ .F32 = v };
        try self.pushValue(typed);
    }

    fn pushF64(self: *Self, v: f64) !void {
        var typed = Val{ .F64 = v };
        try self.pushValue(typed);
    }

    fn popValue(self: *Self) !Val {
        self.num_values -= 1;
        var value: Val = self.values[self.num_values];
        return value;
    }

    fn topValue(self: *const Self) !Val {
        var value: Val = self.values[self.num_values - 1];
        return value;
    }

    fn popI32(self: *Self) !i32 {
        var value: Val = try self.popValue();
        return value.I32;
    }

    fn popI64(self: *Self) !i64 {
        var value: Val = try self.popValue();
        return value.I64;
    }

    fn popF32(self: *Self) !f32 {
        var value: Val = try self.popValue();
        return value.F32;
    }

    fn popF64(self: *Self) !f64 {
        var value: Val = try self.popValue();
        return value.F64;
    }

    fn pushLabel(self: *Self, num_returns: u32, continuation: u32) !void {
        if (self.num_labels < self.labels.len) {
            self.labels[self.num_labels] = Label{
                .num_returns = num_returns,
                .continuation = continuation,
                .start_offset_values = self.num_values,
            };
            self.num_labels += 1;
        } else {
            return error.TrapStackExhausted;
        }
    }

    fn popLabel(self: *Self) void {
        self.num_labels -= 1;
    }

    fn findLabel(self: *const Self, id: u32) *const Label {
        const index: usize = (self.num_labels - 1) - id;
        return &self.labels[index];
    }

    fn topLabel(self: *const Self) *const Label {
        return &self.labels[self.num_labels - 1];
    }

    fn frameLabel(self: *const Self) *const Label {
        var frame: *const CallFrame = self.topFrame();
        var frame_label: *const Label = &self.labels[frame.start_offset_labels];
        return frame_label;
    }

    fn popAllUntilLabelId(self: *Self, label_id: u64, pop_final_label: bool, num_returns: usize) void {
        var label_index: u16 = @intCast(u16, (self.num_labels - label_id) - 1);
        var label: *const Label = &self.labels[label_index];

        if (pop_final_label) {
            const source_begin: usize = self.num_values - num_returns;
            const source_end: usize = self.num_values;
            const dest_begin: usize = label.start_offset_values;
            const dest_end: usize = label.start_offset_values + num_returns;

            const returns_source: []const Val = self.values[source_begin..source_end];
            const returns_dest: []Val = self.values[dest_begin..dest_end];
            std.mem.copy(Val, returns_dest, returns_source);

            self.num_values = @intCast(u32, dest_end);
            self.num_labels = label_index;
        } else {
            self.num_values = label.start_offset_values;
            self.num_labels = label_index + 1;
        }
    }

    fn pushFrame(self: *Self, func: *const FunctionInstance, module_instance: *ModuleInstance, param_types: []const ValType, all_local_types: []const ValType) !void {
        const non_param_types: []const ValType = all_local_types[param_types.len..];

        // the stack should already be populated with the params to the function, so all that's
        // left to do is initialize the locals to their default values
        var values_index_begin: u32 = self.num_values - @intCast(u32, param_types.len);
        var values_index_end: u32 = self.num_values + @intCast(u32, non_param_types.len);

        if (self.num_frames < self.frames.len and values_index_end < self.values.len) {
            var locals_and_params: []Val = self.values[values_index_begin..values_index_end];
            var locals = self.values[self.num_values..values_index_end];

            self.num_values = values_index_end;

            for (non_param_types) |valtype, i| {
                locals[i] = Val.default(valtype);
            }

            self.frames[self.num_frames] = CallFrame{
                .func = func,
                .module_instance = module_instance,
                .locals = locals_and_params,
                .start_offset_values = values_index_begin,
                .start_offset_labels = self.num_labels,
            };
            self.num_frames += 1;
        } else {
            return error.TrapStackExhausted;
        }
    }

    fn popFrame(self: *Self) ?FuncCallData {
        var frame: *CallFrame = self.topFrame();
        var frame_label: Label = self.labels[frame.start_offset_labels];

        const return_types: []const ValType = frame.module_instance.module_def.types.items[frame.func.type_def_index].getReturns();
        const num_returns: usize = return_types.len;

        const source_begin: usize = self.num_values - num_returns;
        const source_end: usize = self.num_values;
        const dest_begin: usize = frame.start_offset_values;
        const dest_end: usize = frame.start_offset_values + num_returns;

        const returns_source: []const Val = self.values[source_begin..source_end];
        const returns_dest: []Val = self.values[dest_begin..dest_end];
        std.mem.copy(Val, returns_dest, returns_source);

        self.num_values = @intCast(u32, dest_end);
        self.num_labels = frame.start_offset_labels;
        self.num_frames -= 1;

        if (self.num_frames > 0) {
            return FuncCallData{
                .code = self.topFrame().module_instance.module_def.code.instructions.items.ptr,
                .continuation = frame_label.continuation,
            };
        }

        return null;
    }

    fn topFrame(self: *const Self) *CallFrame {
        return &self.frames[self.num_frames - 1];
    }

    fn popAll(self: *Self) void {
        self.num_values = 0;
        self.num_labels = 0;
        self.num_frames = 0;
    }
};

const Section = enum(u8) { Custom, FunctionType, Import, Function, Table, Memory, Global, Export, Start, Element, Code, Data, DataCount };

const k_function_type_sentinel_byte: u8 = 0x60;
const k_block_type_void_sentinel_byte: u8 = 0x40;

fn decodeLEB128(comptime T: type, reader: anytype) !T {
    if (@typeInfo(T).Int.signedness == .signed) {
        return std.leb.readILEB128(T, reader) catch |e| {
            if (e == error.Overflow) {
                return error.MalformedLEB128;
            } else {
                return e;
            }
        };
    } else {
        return std.leb.readULEB128(T, reader) catch |e| {
            if (e == error.Overflow) {
                return error.MalformedLEB128;
            } else {
                return e;
            }
        };
    }
}

fn decodeFloat(comptime T: type, reader: anytype) !T {
    return switch (T) {
        f32 => @bitCast(f32, try reader.readIntLittle(u32)),
        f64 => @bitCast(f64, try reader.readIntLittle(u64)),
        else => unreachable,
    };
}

const ConstantExpressionType = enum {
    Value,
    Global,
};

const ConstantExpression = union(ConstantExpressionType) {
    Value: Val,
    Global: u32, // global index

    const ExpectedGlobalMut = enum {
        Any,
        Immutable,
    };

    fn decode(reader: anytype, module_def: *const ModuleDefinition, comptime expected_global_mut: ExpectedGlobalMut, expected_valtype: ValType) !ConstantExpression {
        const opcode_value = try reader.readByte();
        const opcode = std.meta.intToEnum(WasmOpcode, opcode_value) catch {
            return error.MalformedIllegalOpcode;
        };

        const expr = switch (opcode) {
            .I32_Const => ConstantExpression{ .Value = Val{ .I32 = try decodeLEB128(i32, reader) } },
            .I64_Const => ConstantExpression{ .Value = Val{ .I64 = try decodeLEB128(i64, reader) } },
            .F32_Const => ConstantExpression{ .Value = Val{ .F32 = try decodeFloat(f32, reader) } },
            .F64_Const => ConstantExpression{ .Value = Val{ .F64 = try decodeFloat(f64, reader) } },
            .Ref_Null => ConstantExpression{ .Value = try Val.nullRef(try ValType.decode(reader)) },
            .Ref_Func => ConstantExpression{ .Value = Val.funcrefFromIndex(try decodeLEB128(u32, reader)) },
            .Global_Get => ConstantExpression{ .Global = try decodeLEB128(u32, reader) },
            else => return error.ValidationBadConstantExpression,
        };

        if (opcode == .Global_Get) {
            try ModuleValidator.validateGlobalIndex(expr.Global, module_def);

            if (module_def.imports.globals.items.len <= expr.Global) {
                return error.ValidationConstantExpressionGlobalMustBeImport;
            }

            if (expected_global_mut == .Immutable) {
                if (expr.Global < module_def.imports.globals.items.len) {
                    if (module_def.imports.globals.items[expr.Global].mut != .Immutable) {
                        return error.ValidationConstantExpressionGlobalMustBeImmutable;
                    }
                } else {
                    const local_index: usize = module_def.imports.globals.items.len - expr.Global;
                    if (module_def.globals.items[local_index].mut != .Immutable) {
                        return error.ValidationConstantExpressionGlobalMustBeImmutable;
                    }
                }
            }

            var global_valtype: ValType = undefined;
            if (expr.Global < module_def.imports.globals.items.len) {
                const global_import_def: *const GlobalImportDefinition = &module_def.imports.globals.items[expr.Global];
                global_valtype = global_import_def.valtype;
            } else {
                const local_index: usize = module_def.imports.globals.items.len - expr.Global;
                const global_def: *const GlobalDefinition = &module_def.globals.items[local_index];
                global_valtype = global_def.valtype;
            }

            if (global_valtype != expected_valtype) {
                return error.ValidationConstantExpressionTypeMismatch;
            }
        } else {
            if (std.meta.activeTag(expr.Value) != expected_valtype) {
                return error.ValidationConstantExpressionTypeMismatch;
            }
        }

        const end = @intToEnum(WasmOpcode, try reader.readByte());
        if (end != .End) {
            return error.ValidationBadConstantExpression;
        }

        return expr;
    }

    fn resolve(self: *const ConstantExpression, store: *Store) !Val {
        switch (self.*) {
            .Value => |val| return val,
            .Global => |global_index| {
                std.debug.assert(global_index < store.imports.globals.items.len + store.globals.items.len);
                const global: *GlobalInstance = store.getGlobal(global_index);
                return global.value;
            },
        }
    }

    fn resolveTo(self: *const ConstantExpression, store: *Store, comptime T: type) !T {
        const val: Val = try self.resolve(store);
        return val.get(T);
    }

    fn resolveType(self: *const ConstantExpression, module_def: *const ModuleDefinition) ValType {
        switch (self.*) {
            .Value => |val| return std.meta.activeTag(val),
            .Global => |index| {
                if (index < module_def.imports.globals.items.len) {
                    const global_import_def: *const GlobalImportDefinition = &module_def.imports.globals.items[index];
                    return global_import_def.valtype;
                } else {
                    const local_index: usize = module_def.imports.globals.items.len - index;
                    const global_def: *const GlobalDefinition = &module_def.globals.items[local_index];
                    return global_def.valtype;
                }
                unreachable;
            },
        }
    }
};

pub const Limits = struct {
    min: u32,
    max: ?u32,

    fn decode(reader: anytype) !Limits {
        const has_max = try reader.readByte();
        if (has_max > 1) {
            return error.MalformedLimits;
        }
        const min = try decodeLEB128(u32, reader);
        var max: ?u32 = null;

        switch (has_max) {
            0 => {},
            1 => {
                max = try decodeLEB128(u32, reader);
                if (max.? < min) {
                    return error.ValidationLimitsMinMustNotBeLargerThanMax;
                }
            },
            else => unreachable,
        }

        return Limits{
            .min = min,
            .max = max,
        };
    }
};

const FunctionTypeDefinition = struct {
    types: std.ArrayList(ValType),
    num_params: u32,

    fn getParams(self: *const FunctionTypeDefinition) []const ValType {
        return self.types.items[0..self.num_params];
    }
    fn getReturns(self: *const FunctionTypeDefinition) []const ValType {
        return self.types.items[self.num_params..];
    }
};

const FunctionTypeContext = struct {
    const Self = @This();

    pub fn hash(_: Self, f: *FunctionTypeDefinition) u64 {
        var seed: u64 = 0;
        if (f.types.items.len > 0) {
            seed = std.hash.Murmur2_64.hash(std.mem.sliceAsBytes(f.types.items));
        }
        return std.hash.Murmur2_64.hashWithSeed(std.mem.asBytes(&f.num_params), seed);
    }

    pub fn eql(_: Self, a: *const FunctionTypeDefinition, b: *const FunctionTypeDefinition) bool {
        if (a.num_params != b.num_params or a.types.items.len != b.types.items.len) {
            return false;
        }

        for (a.types.items) |typeA, i| {
            var typeB = b.types.items[i];
            if (typeA != typeB) {
                return false;
            }
        }

        return true;
    }

    fn less(context: Self, a: *FunctionTypeDefinition, b: *FunctionTypeDefinition) bool {
        var ord = Self.order(context, a, b);
        return ord == std.math.Order.lt;
    }

    fn order(context: Self, a: *FunctionTypeDefinition, b: *FunctionTypeDefinition) std.math.Order {
        var hashA = Self.hash(context, a);
        var hashB = Self.hash(context, b);

        if (hashA < hashB) {
            return std.math.Order.lt;
        } else if (hashA > hashB) {
            return std.math.Order.gt;
        } else {
            return std.math.Order.eq;
        }
    }
};

const FunctionDefinition = struct {
    type_index: u32,
    offset_into_instructions: u32,
    continuation: u32,
    locals: std.ArrayList(ValType),
    size: u32,
};

const FunctionInstance = struct {
    type_def_index: u32,
    def_index: u32,
    offset_into_instructions: u32,
    local_types: std.ArrayList(ValType),
};

const ExportType = enum(u8) {
    Function = 0x00,
    Table = 0x01,
    Memory = 0x02,
    Global = 0x03,
};

const ExportDefinition = struct {
    name: []const u8,
    index: u32,
};

pub const GlobalMut = enum(u8) {
    Immutable = 0,
    Mutable = 1,

    fn decode(reader: anytype) !GlobalMut {
        const byte = try reader.readByte();
        const value = std.meta.intToEnum(GlobalMut, byte) catch {
            return error.MalformedMutability;
        };
        return value;
    }
};

const GlobalDefinition = struct {
    valtype: ValType,
    mut: GlobalMut,
    expr: ConstantExpression,
};

pub const GlobalInstance = struct {
    mut: GlobalMut,
    value: Val,
};

const TableDefinition = struct {
    reftype: ValType,
    limits: Limits,
};

pub const TableInstance = struct {
    refs: std.ArrayList(Val), // should only be reftypes
    reftype: ValType,
    limits: Limits,

    pub fn init(reftype: ValType, limits: Limits, allocator: std.mem.Allocator) !TableInstance {
        std.debug.assert(reftype.isRefType());

        var table = TableInstance{
            .refs = std.ArrayList(Val).init(allocator),
            .reftype = reftype,
            .limits = limits,
        };

        if (limits.min > 0) {
            try table.refs.appendNTimes(try Val.nullRef(reftype), limits.min);
        }
        return table;
    }

    pub fn deinit(table: *TableInstance) void {
        table.refs.deinit();
    }

    fn grow(table: *TableInstance, length: usize, init_value: Val) bool {
        const max = if (table.limits.max) |m| m else std.math.maxInt(i32);
        std.debug.assert(table.refs.items.len == table.limits.min);

        var old_length: usize = table.limits.min;
        if (old_length + length > max) {
            return false;
        }

        table.limits.min = @intCast(u32, old_length + length);

        table.refs.appendNTimes(init_value, length) catch return false;
        return true;
    }

    fn init_range_val(table: *TableInstance, module: *ModuleInstance, elems: []const Val, init_length: u32, start_elem_index: u32, start_table_index: u32) !void {
        if (table.refs.items.len < start_table_index + init_length) {
            return error.TrapOutOfBoundsTableAccess;
        }

        if (elems.len < start_elem_index + init_length) {
            return error.TrapOutOfBoundsTableAccess;
        }

        var elem_range = elems[start_elem_index .. start_elem_index + init_length];
        var table_range = table.refs.items[start_table_index .. start_table_index + init_length];

        var index: u32 = 0;
        while (index < elem_range.len) : (index += 1) {
            var val: Val = elem_range[index];
            std.debug.assert(std.meta.activeTag(val) == table.reftype);

            if (table.reftype == .FuncRef) {
                val.FuncRef.module_instance = module;
            }

            table_range[index] = val;
        }
    }

    fn init_range_expr(table: *TableInstance, module: *ModuleInstance, elems: []const ConstantExpression, init_length: u32, start_elem_index: u32, start_table_index: u32, store: *Store) !void {
        if (start_table_index < 0 or table.refs.items.len < start_table_index + init_length) {
            return error.TrapOutOfBoundsTableAccess;
        }

        if (start_elem_index < 0 or elems.len < start_elem_index + init_length) {
            return error.TrapOutOfBoundsTableAccess;
        }

        var elem_range = elems[start_elem_index .. start_elem_index + init_length];
        var table_range = table.refs.items[start_table_index .. start_table_index + init_length];

        var index: u32 = 0;
        while (index < elem_range.len) : (index += 1) {
            var val: Val = try elem_range[index].resolve(store);
            std.debug.assert(std.meta.activeTag(val) == table.reftype);

            if (table.reftype == .FuncRef) {
                val.FuncRef.module_instance = module;
            }

            table_range[index] = val;
        }
    }
};

const MemoryDefinition = struct {
    limits: Limits,
};

pub const MemoryInstance = struct {
    const k_page_size: usize = 64 * 1024;
    const k_max_pages: usize = std.math.powi(usize, 2, 16) catch unreachable;

    limits: Limits,
    mem: StableArray(u8),

    pub fn init(limits: Limits) MemoryInstance {
        const max_pages = if (limits.max) |max| std.math.max(1, max) else k_max_pages;

        var instance = MemoryInstance{
            .limits = Limits{ .min = 0, .max = @intCast(u32, max_pages) },
            .mem = StableArray(u8).init(max_pages * k_page_size),
        };

        return instance;
    }

    pub fn deinit(self: *MemoryInstance) void {
        self.mem.deinit();
    }

    pub fn size(self: *const MemoryInstance) usize {
        return self.mem.items.len / k_page_size;
    }

    pub fn grow(self: *MemoryInstance, num_pages: usize) bool {
        if (num_pages == 0) {
            return true;
        }

        const total_pages = self.limits.min + num_pages;
        const max_pages = if (self.limits.max) |max| max else k_max_pages;

        if (total_pages > max_pages) {
            return false;
        }

        const commit_size: usize = (self.limits.min + num_pages) * k_page_size;

        self.mem.resize(commit_size) catch return false;

        self.limits.min = @intCast(u32, total_pages);

        return true;
    }

    fn ensureMinSize(self: *MemoryInstance, size_bytes: usize) !void {
        if (self.limits.min * k_page_size < size_bytes) {
            var num_min_pages = std.math.divCeil(usize, size_bytes, k_page_size) catch unreachable;
            if (num_min_pages > self.limits.max.?) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            var needed_pages = num_min_pages - self.limits.min;
            if (self.grow(needed_pages) == false) {
                unreachable;
            }
        }
    }
};

const ElementMode = enum {
    Active,
    Passive,
    Declarative,
};

const ElementDefinition = struct {
    table_index: u32,
    mode: ElementMode,
    reftype: ValType,
    offset: ?ConstantExpression,
    elems_value: std.ArrayList(Val),
    elems_expr: std.ArrayList(ConstantExpression),
};

const ElementInstance = struct {
    refs: std.ArrayList(Val),
    reftype: ValType,
};

const DataMode = enum {
    Active,
    Passive,
};

const DataDefinition = struct {
    bytes: std.ArrayList(u8),
    memory_index: ?u32,
    offset: ?ConstantExpression,
    mode: DataMode,

    fn decode(reader: anytype, module_def: *const ModuleDefinition, allocator: std.mem.Allocator) !DataDefinition {
        var data_type: u32 = try decodeLEB128(u32, reader);
        if (data_type > 2) {
            return error.MalformedDataType;
        }

        var memory_index: ?u32 = null;
        if (data_type == 0x00) {
            memory_index = 0;
        } else if (data_type == 0x02) {
            memory_index = try decodeLEB128(u32, reader);
        }

        var mode = DataMode.Passive;
        var offset: ?ConstantExpression = null;
        if (data_type == 0x00 or data_type == 0x02) {
            mode = DataMode.Active;
            offset = try ConstantExpression.decode(reader, module_def, .Immutable, .I32);
        }

        var num_bytes = try decodeLEB128(u32, reader);
        var bytes = std.ArrayList(u8).init(allocator);
        try bytes.resize(num_bytes);
        var num_read = try reader.read(bytes.items);
        if (num_read != num_bytes) {
            return error.MalformedUnexpectedEnd;
        }

        if (memory_index) |index| {
            if (module_def.imports.memories.items.len + module_def.memories.items.len <= index) {
                return error.ValidationUnknownMemory;
            }
        }

        return DataDefinition{
            .bytes = bytes,
            .memory_index = memory_index,
            .offset = offset,
            .mode = mode,
        };
    }
};

const ImportNames = struct {
    module_name: []const u8,
    import_name: []const u8,
};

const FunctionImportDefinition = struct {
    names: ImportNames,
    type_index: u32,
};

const TableImportDefinition = struct {
    names: ImportNames,
    reftype: ValType,
    limits: Limits,
};

const MemoryImportDefinition = struct {
    names: ImportNames,
    limits: Limits,
};

const GlobalImportDefinition = struct {
    names: ImportNames,
    valtype: ValType,
    mut: GlobalMut,
};

const MemArg = struct {
    alignment: u32,
    offset: u32,

    fn decode(reader: anytype, comptime bitwidth: u32) !MemArg {
        std.debug.assert(bitwidth % 8 == 0);
        var memarg = MemArg{
            .alignment = try decodeLEB128(u32, reader),
            .offset = try decodeLEB128(u32, reader),
        };
        const bit_alignment = std.math.powi(u32, 2, memarg.alignment) catch return error.ValidationBadAlignment;
        if (bit_alignment > bitwidth / 8) {
            return error.ValidationBadAlignment;
        }
        return memarg;
    }
};

const U32Pair = struct {
    a: u32,
    b: u32,

    fn toU64(a: u32, b: u32) u64 {
        var aa: u64 = a;
        var bb: u64 = b;
        return aa | (bb << 32);
    }

    fn fromU64(v: u64) U32Pair {
        return U32Pair{
            .a = @truncate(u32, v),
            .b = @truncate(u32, v >> 32),
        };
    }
};

const CallIndirectImmediates = struct {
    type_index: u32,
    table_index: u32,

    fn toU64(immediates: CallIndirectImmediates) u64 {
        return U32Pair.toU64(immediates.type_index, immediates.table_index);
    }

    fn fromU64(value: u64) CallIndirectImmediates {
        var pair: U32Pair = U32Pair.fromU64(value);
        return CallIndirectImmediates{
            .type_index = pair.a,
            .table_index = pair.b,
        };
    }
};

const BranchTableImmediates = struct {
    label_ids: std.ArrayList(u32), // TODO optimize to make less allocations
    fallback_id: u32,
};

const TablePairImmediates = struct {
    index_x: u32,
    index_y: u32,

    fn toU64(immediates: TablePairImmediates) u64 {
        return U32Pair.toU64(immediates.index_x, immediates.index_y);
    }

    fn fromU64(value: u64) TablePairImmediates {
        var pair: U32Pair = U32Pair.fromU64(value);
        return TablePairImmediates{
            .index_x = pair.a,
            .index_y = pair.b,
        };
    }
};

const BlockImmediates = struct {
    blocktype: BlockTypeValue,
    num_returns: u32,
    continuation: u32,

    fn toU64(immediates: BlockImmediates) u64 {
        return U32Pair.toU64(immediates.num_returns, immediates.continuation);
    }

    fn fromU64(value: u64) BlockImmediates {
        var pair: U32Pair = U32Pair.fromU64(value);
        return BlockImmediates{
            .blocktype = BlockTypeValue{ .Void = {} }, // unused in the places we're converting back from u64
            .num_returns = pair.a,
            .continuation = pair.b,
        };
    }
};

const InstructionImmediatesTypes = enum(u8) {
    Void,
    ValType,
    ValueI32,
    ValueF32,
    ValueI64,
    ValueF64,
    Index,
    LabelId,
    MemoryOffset,
    Block,
    CallIndirect,
    TablePair,
};

const InstructionImmediates = union(InstructionImmediatesTypes) {
    Void: void,
    ValType: ValType,
    ValueI32: i32,
    ValueF32: f32,
    ValueI64: i64,
    ValueF64: f64,
    Index: u32,
    LabelId: u32,
    MemoryOffset: u32,
    Block: BlockImmediates,
    CallIndirect: CallIndirectImmediates,
    TablePair: TablePairImmediates,
};

const Instruction = struct {
    opcode: Opcode,
    immediate: InstructionImmediates,

    fn decode(reader: anytype, module: *ModuleDefinition) !Instruction {
        const Helpers = struct {
            fn decodeBlockType(_reader: anytype, _module: *const ModuleDefinition) !InstructionImmediates {
                var blocktype: BlockTypeValue = undefined;

                const blocktype_raw = try _reader.readByte();
                const valtype_or_err = ValType.bytecodeToValtype(blocktype_raw);
                if (std.meta.isError(valtype_or_err)) {
                    if (blocktype_raw == k_block_type_void_sentinel_byte) {
                        blocktype = BlockTypeValue{ .Void = {} };
                    } else {
                        _reader.context.pos -= 1; // move the stream backwards 1 byte to reconstruct the integer
                        var index_33bit = try decodeLEB128(i33, _reader);
                        if (index_33bit < 0) {
                            return error.AssertInvalidBytecode;
                        }
                        var index: u32 = @intCast(u32, index_33bit);
                        if (index < _module.types.items.len) {
                            blocktype = BlockTypeValue{ .TypeIndex = index };
                        } else {
                            return error.ValidationUnknownBlockTypeIndex;
                        }
                    }
                } else {
                    var valtype: ValType = valtype_or_err catch unreachable;
                    blocktype = BlockTypeValue{ .ValType = valtype };
                }

                const num_returns: u32 = @intCast(u32, blocktype.getBlocktypeReturnTypes(_module).len);

                return InstructionImmediates{
                    .Block = BlockImmediates{
                        .blocktype = blocktype,
                        .num_returns = num_returns,
                        .continuation = std.math.maxInt(u32), // will be set later in the code decode
                    },
                };
            }

            fn decodeTablePair(_reader: anytype) !InstructionImmediates {
                const elem_index = try decodeLEB128(u32, _reader);
                const table_index = try decodeLEB128(u32, _reader);

                return InstructionImmediates{
                    .TablePair = TablePairImmediates{
                        .index_x = elem_index,
                        .index_y = table_index,
                    },
                };
            }
        };

        var byte = try reader.readByte();
        var wasm_op: WasmOpcode = undefined;
        if (byte == 0xFC) {
            var type_opcode = try decodeLEB128(u32, reader);
            if (type_opcode > std.math.maxInt(u8)) {
                return error.MalformedIllegalOpcode;
            }
            var byte2 = @intCast(u8, type_opcode);
            var extended: u16 = byte;
            extended = extended << 8;
            extended |= byte2;

            wasm_op = std.meta.intToEnum(WasmOpcode, extended) catch {
                return error.MalformedIllegalOpcode;
            };
        } else {
            wasm_op = std.meta.intToEnum(WasmOpcode, byte) catch {
                return error.MalformedIllegalOpcode;
            };
        }

        var opcode: Opcode = wasm_op.toOpcode();
        var immediate = InstructionImmediates{ .Void = {} };

        switch (opcode) {
            .Select_T => {
                const num_types = try decodeLEB128(u32, reader);
                if (num_types != 1) {
                    return error.ValidationSelectArity;
                }
                immediate = InstructionImmediates{ .ValType = try ValType.decode(reader) };
            },
            .Local_Get => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) };
            },
            .Local_Set => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) };
            },
            .Local_Tee => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) };
            },
            .Global_Get => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) };
            },
            .Global_Set => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) };
            },
            .Table_Get => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) };
            },
            .Table_Set => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) };
            },
            .I32_Const => {
                immediate = InstructionImmediates{ .ValueI32 = try decodeLEB128(i32, reader) };
            },
            .I64_Const => {
                immediate = InstructionImmediates{ .ValueI64 = try decodeLEB128(i64, reader) };
            },
            .F32_Const => {
                immediate = InstructionImmediates{ .ValueF32 = try decodeFloat(f32, reader) };
            },
            .F64_Const => {
                immediate = InstructionImmediates{ .ValueF64 = try decodeFloat(f64, reader) };
            },
            .Block => {
                immediate = try Helpers.decodeBlockType(reader, module);
            },
            .Loop => {
                immediate = try Helpers.decodeBlockType(reader, module);
            },
            .If => {
                immediate = try Helpers.decodeBlockType(reader, module);
            },
            .Branch => {
                immediate = InstructionImmediates{ .LabelId = try decodeLEB128(u32, reader) };
            },
            .Branch_If => {
                immediate = InstructionImmediates{ .LabelId = try decodeLEB128(u32, reader) };
            },
            .Branch_Table => {
                const table_length = try decodeLEB128(u32, reader);

                var label_ids = std.ArrayList(u32).init(module.allocator);
                try label_ids.ensureTotalCapacity(table_length);

                var index: u32 = 0;
                while (index < table_length) : (index += 1) {
                    var id = try decodeLEB128(u32, reader);
                    label_ids.addOneAssumeCapacity().* = id;
                }
                var fallback_id = try decodeLEB128(u32, reader);

                var branch_table = BranchTableImmediates{
                    .label_ids = label_ids,
                    .fallback_id = fallback_id,
                };

                for (module.code.branch_table.items) |*item, i| {
                    if (item.fallback_id == branch_table.fallback_id) {
                        if (std.mem.eql(u32, item.label_ids.items, branch_table.label_ids.items)) {
                            immediate = InstructionImmediates{ .Index = @intCast(u32, i) };
                            break;
                        }
                    }
                }

                if (std.meta.activeTag(immediate) == .Void) {
                    immediate = InstructionImmediates{ .Index = @intCast(u32, module.code.branch_table.items.len) };
                    try module.code.branch_table.append(branch_table);
                }
            },
            .Call => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // function index
            },
            .Call_Indirect => {
                immediate = InstructionImmediates{ .CallIndirect = .{
                    .type_index = try decodeLEB128(u32, reader),
                    .table_index = try decodeLEB128(u32, reader),
                } };
            },
            .I32_Load => {
                var memarg = try MemArg.decode(reader, 32);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Load => {
                var memarg = try MemArg.decode(reader, 64);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .F32_Load => {
                var memarg = try MemArg.decode(reader, 32);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .F64_Load => {
                var memarg = try MemArg.decode(reader, 64);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I32_Load8_S => {
                var memarg = try MemArg.decode(reader, 8);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I32_Load8_U => {
                var memarg = try MemArg.decode(reader, 8);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I32_Load16_S => {
                var memarg = try MemArg.decode(reader, 16);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I32_Load16_U => {
                var memarg = try MemArg.decode(reader, 16);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Load8_S => {
                var memarg = try MemArg.decode(reader, 8);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Load8_U => {
                var memarg = try MemArg.decode(reader, 8);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Load16_S => {
                var memarg = try MemArg.decode(reader, 16);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Load16_U => {
                var memarg = try MemArg.decode(reader, 16);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Load32_S => {
                var memarg = try MemArg.decode(reader, 32);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Load32_U => {
                var memarg = try MemArg.decode(reader, 32);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I32_Store => {
                var memarg = try MemArg.decode(reader, 32);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Store => {
                var memarg = try MemArg.decode(reader, 64);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .F32_Store => {
                var memarg = try MemArg.decode(reader, 32);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .F64_Store => {
                var memarg = try MemArg.decode(reader, 64);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I32_Store8 => {
                var memarg = try MemArg.decode(reader, 8);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I32_Store16 => {
                var memarg = try MemArg.decode(reader, 16);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Store8 => {
                var memarg = try MemArg.decode(reader, 8);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Store16 => {
                var memarg = try MemArg.decode(reader, 16);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .I64_Store32 => {
                var memarg = try MemArg.decode(reader, 32);
                immediate = InstructionImmediates{ .MemoryOffset = memarg.offset };
            },
            .Memory_Size => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.MalformedMissingZeroByte;
                }
            },
            .Memory_Grow => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.MalformedMissingZeroByte;
                }
            },
            .Memory_Init => {
                try ModuleValidator.validateMemoryIndex(module);

                if (module.data_count == null) {
                    return error.MalformedMissingDataCountSection;
                }

                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // dataidx

                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.MalformedMissingZeroByte;
                }
            },
            .Ref_Null => {
                var valtype = try ValType.decode(reader);
                if (valtype.isRefType() == false) {
                    return error.AssertInvalidBytecode;
                }

                immediate = InstructionImmediates{ .ValType = valtype };
                // immediate = @enumToInt(valtype);
            },
            .Ref_Func => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // funcidx
            },
            .Data_Drop => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // dataidx
            },
            .Memory_Copy => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.MalformedMissingZeroByte;
                }
                reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.MalformedMissingZeroByte;
                }
            },
            .Memory_Fill => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.MalformedMissingZeroByte;
                }
            },
            .Table_Init => {
                immediate = try Helpers.decodeTablePair(reader);
            },
            .Elem_Drop => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // elemidx
            },
            .Table_Copy => {
                immediate = try Helpers.decodeTablePair(reader);
            },
            .Table_Grow => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // elemidx
            },
            .Table_Size => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // elemidx
            },
            .Table_Fill => {
                immediate = InstructionImmediates{ .Index = try decodeLEB128(u32, reader) }; // elemidx
            },
            else => {},
        }

        return .{
            .opcode = opcode,
            .immediate = immediate,
        };
    }
};

const CustomSection = struct {
    name: []const u8,
    data: std.ArrayList(u8),
};

const ModuleValidator = struct {
    const ControlFrame = struct {
        opcode: Opcode,
        start_types: []const ValType,
        end_types: []const ValType,
        types_stack_height: usize,
        is_function: bool,
        is_unreachable: bool,
    };

    // Note that we use a nullable ValType here to map to the "Unknown" value type as described in the wasm spec
    // validation algorithm: https://webassembly.github.io/spec/core/appendix/algorithm.html
    type_stack: std.ArrayList(?ValType),
    control_stack: std.ArrayList(ControlFrame),
    control_types: StableArray(ValType),

    fn init(allocator: std.mem.Allocator) ModuleValidator {
        return ModuleValidator{
            .type_stack = std.ArrayList(?ValType).init(allocator),
            .control_stack = std.ArrayList(ControlFrame).init(allocator),
            .control_types = StableArray(ValType).init(1 * 1024 * 1024),
        };
    }

    fn deinit(self: *ModuleValidator) void {
        self.type_stack.deinit();
        self.control_stack.deinit();
        self.control_types.deinit();
    }

    fn validateTypeIndex(index: u64, module: *const ModuleDefinition) !void {
        if (module.types.items.len <= index) {
            return error.ValidationUnknownType;
        }
    }

    fn validateGlobalIndex(index: u64, module: *const ModuleDefinition) !void {
        if (module.imports.globals.items.len + module.globals.items.len <= index) {
            return error.ValidationUnknownGlobal;
        }
    }

    fn validateTableIndex(index: u64, module: *const ModuleDefinition) !void {
        if (module.imports.tables.items.len + module.tables.items.len <= index) {
            return error.ValidationUnknownTable;
        }
    }

    fn getTableReftype(module: *const ModuleDefinition, index: u64) !ValType {
        if (index < module.imports.tables.items.len) {
            return module.imports.tables.items[index].reftype;
        }

        const local_index = index - module.imports.tables.items.len;
        if (local_index < module.tables.items.len) {
            return module.tables.items[local_index].reftype;
        }

        return error.ValidationUnknownTable;
    }

    fn validateFunctionIndex(index: u64, module: *const ModuleDefinition) !void {
        if (module.imports.functions.items.len + module.functions.items.len <= index) {
            return error.ValidationUnknownFunction;
        }
    }

    fn validateMemoryIndex(module: *const ModuleDefinition) !void {
        if (module.imports.memories.items.len + module.memories.items.len < 1) {
            return error.ValidationUnknownMemory;
        }
    }

    fn validateElementIndex(index: u64, module: *const ModuleDefinition) !void {
        if (module.elements.items.len <= index) {
            return error.ValidationUnknownElement;
        }
    }

    fn validateDataIndex(index: u64, module: *const ModuleDefinition) !void {
        if (module.data_count.? <= index) {
            return error.ValidationUnknownData;
        }
    }

    fn beginValidateCode(self: *ModuleValidator, module: *const ModuleDefinition, func: *const FunctionDefinition) !void {
        try validateTypeIndex(func.type_index, module);

        const func_type_def: *const FunctionTypeDefinition = &module.types.items[func.type_index];

        try self.pushControl(Opcode.Call, func_type_def.getParams(), func_type_def.getReturns());
    }

    fn validateCode(self: *ModuleValidator, module: *const ModuleDefinition, func: *const FunctionDefinition, instruction: Instruction) !void {
        const Helpers = struct {
            fn popReturnTypes(validator: *ModuleValidator, types: []const ValType) !void {
                var i = types.len;
                while (i > 0) {
                    i -= 1;
                    try validator.popType(types[i]);
                }
            }

            fn enterBlock(validator: *ModuleValidator, module_: *const ModuleDefinition, instruction_: Instruction) !void {
                const blocktype: BlockTypeValue = instruction_.immediate.Block.blocktype;

                var start_types: []const ValType = blocktype.getBlocktypeParamTypes(module_);
                var end_types: []const ValType = blocktype.getBlocktypeReturnTypes(module_);
                try popReturnTypes(validator, start_types);

                try validator.pushControl(instruction_.opcode, start_types, end_types);
            }

            fn getLocalValtype(validator: *const ModuleValidator, module_: *const ModuleDefinition, func_: *const FunctionDefinition, locals_index: u64) !ValType {
                var i = validator.control_stack.items.len - 1;
                while (i >= 0) : (i -= 1) {
                    const frame: *const ControlFrame = &validator.control_stack.items[i];
                    if (frame.is_function) {
                        const func_type: *const FunctionTypeDefinition = &module_.types.items[func_.type_index];
                        if (locals_index < func_type.num_params) {
                            return func_type.getParams()[locals_index];
                        } else {
                            if (func_.locals.items.len <= locals_index - func_type.num_params) {
                                return error.ValidationUnknownLocal;
                            }
                            return func_.locals.items[locals_index - func_type.num_params];
                        }
                    }
                }
                unreachable;
            }

            const GlobalMutablilityRequirement = enum {
                None,
                Mutable,
            };

            fn getGlobalValtype(module_: *const ModuleDefinition, global_index: u64, required_mutability: GlobalMutablilityRequirement) !ValType {
                if (global_index < module_.imports.globals.items.len) {
                    const global: *const GlobalImportDefinition = &module_.imports.globals.items[global_index];
                    if (required_mutability == .Mutable and global.mut == .Immutable) {
                        return error.ValidationImmutableGlobal;
                    }
                    return global.valtype;
                }

                const module_global_index = global_index - module_.imports.globals.items.len;
                if (module_global_index < module_.globals.items.len) {
                    const global: *const GlobalDefinition = &module_.globals.items[module_global_index];
                    if (required_mutability == .Mutable and global.mut == .Immutable) {
                        return error.ValidationImmutableGlobal;
                    }
                    return global.valtype;
                }

                return error.ValidationUnknownGlobal;
            }

            fn validateNumericUnaryOp(validator: *ModuleValidator, pop_type: ValType, push_type: ValType) !void {
                try validator.popType(pop_type);
                try validator.pushType(push_type);
            }

            fn validateNumericBinaryOp(validator: *ModuleValidator, pop_type: ValType, push_type: ValType) !void {
                try validator.popType(pop_type);
                try validator.popType(pop_type);
                try validator.pushType(push_type);
            }

            fn validateStoreOp(validator: *ModuleValidator, module_: *const ModuleDefinition, store_type: ValType) !void {
                try validateMemoryIndex(module_);
                try validator.popType(store_type);
                try validator.popType(.I32);
            }

            fn getControlTypes(validator: *ModuleValidator, control_index: usize) ![]const ValType {
                if (validator.control_stack.items.len <= control_index) {
                    return error.ValidationUnknownLabel;
                }
                const stack_index = validator.control_stack.items.len - control_index - 1;
                var frame: *ControlFrame = &validator.control_stack.items[stack_index];
                return if (frame.opcode != .Loop) frame.end_types else frame.start_types;
            }

            fn markFrameInstructionsUnreachable(validator: *ModuleValidator) !void {
                var frame: *ControlFrame = &validator.control_stack.items[validator.control_stack.items.len - 1];
                try validator.type_stack.resize(frame.types_stack_height);
                frame.is_unreachable = true;
            }

            fn popPushFuncTypes(validator: *ModuleValidator, type_index: u32, module_: *const ModuleDefinition) !void {
                const func_type: *const FunctionTypeDefinition = &module_.types.items[type_index];

                try popReturnTypes(validator, func_type.getParams());
                for (func_type.getReturns()) |valtype| {
                    try validator.pushType(valtype);
                }
            }
        };
        switch (instruction.opcode) {
            .Invalid => unreachable,
            .Unreachable => {
                try Helpers.markFrameInstructionsUnreachable(self);
            },
            .Noop => {},
            .Drop => {
                _ = try self.popAnyType();
            },
            .Block => {
                try Helpers.enterBlock(self, module, instruction);
            },
            .Loop => {
                try Helpers.enterBlock(self, module, instruction);
            },
            .If => {
                try self.popType(.I32);
                try Helpers.enterBlock(self, module, instruction);
            },
            .Else => {
                const frame: ControlFrame = try self.popControl();
                if (frame.opcode != .If) {
                    return error.ValidationIfElseMismatch;
                }
                try self.pushControl(.Else, frame.start_types, frame.end_types);
            },
            .End => {
                const frame: ControlFrame = try self.popControl();

                // if must have matching else block when returns are expected and the params don't match
                if (frame.opcode == .If and !std.mem.eql(ValType, frame.start_types, frame.end_types)) {
                    return error.ValidationTypeMismatch;
                }

                if (self.control_stack.items.len > 0) {
                    for (frame.end_types) |valtype| {
                        try self.pushType(valtype);
                    }
                }
                try self.freeControlTypes(&frame);
            },
            .Branch => {
                const control_index: u64 = instruction.immediate.LabelId;
                const block_return_types: []const ValType = try Helpers.getControlTypes(self, control_index);

                try Helpers.popReturnTypes(self, block_return_types);
                try Helpers.markFrameInstructionsUnreachable(self);
            },
            .Branch_If => {
                const control_index: u64 = instruction.immediate.LabelId;
                const block_return_types: []const ValType = try Helpers.getControlTypes(self, control_index);
                try self.popType(.I32);

                try Helpers.popReturnTypes(self, block_return_types);
                for (block_return_types) |valtype| {
                    try self.pushType(valtype);
                }
            },
            .Branch_Table => {
                var immediates: *const BranchTableImmediates = &module.code.branch_table.items[instruction.immediate.Index];

                const fallback_block_return_types: []const ValType = try Helpers.getControlTypes(self, immediates.fallback_id);

                try self.popType(.I32);

                for (immediates.label_ids.items) |control_index| {
                    const block_return_types: []const ValType = try Helpers.getControlTypes(self, control_index);

                    if (fallback_block_return_types.len != block_return_types.len) {
                        return error.ValidationTypeMismatch;
                    }

                    // Seems like the wabt validation code for br_table is implemented by "peeking" at types on the stack
                    // instead of actually popping/pushing them. This allows certain block type mismatches to be considered
                    // valid when the current block is marked unreachable.
                    const frame: *const ControlFrame = &self.control_stack.items[control_index];
                    const type_stack: []const ?ValType = self.type_stack.items[frame.types_stack_height..];

                    var i: usize = block_return_types.len;
                    while (i > 0) : (i -= 1) {
                        if (!frame.is_unreachable and frame.types_stack_height < type_stack.len) {
                            if (type_stack[type_stack.len - i] != block_return_types[block_return_types.len - i]) {
                                return error.ValidationTypeMismatch;
                            }
                        }
                    }
                }

                try Helpers.popReturnTypes(self, fallback_block_return_types);
                try Helpers.markFrameInstructionsUnreachable(self);
            },
            .Return => {
                const block_return_types: []const ValType = try Helpers.getControlTypes(self, self.control_stack.items.len - 1);
                try Helpers.popReturnTypes(self, block_return_types);
                try Helpers.markFrameInstructionsUnreachable(self);
            },
            .Call => {
                const func_index: u64 = instruction.immediate.Index;
                if (module.imports.functions.items.len + module.functions.items.len <= func_index) {
                    return error.ValidationUnknownFunction;
                }

                var type_index: u32 = undefined;
                if (func_index < module.imports.functions.items.len) {
                    const func_def: *const FunctionImportDefinition = &module.imports.functions.items[func_index];
                    type_index = func_def.type_index;
                } else {
                    const module_func_index = func_index - module.imports.functions.items.len;
                    const func_def: *const FunctionDefinition = &module.functions.items[module_func_index];
                    type_index = func_def.type_index;
                }

                try Helpers.popPushFuncTypes(self, type_index, module);
            },
            .Call_Indirect => {
                const immediates: CallIndirectImmediates = instruction.immediate.CallIndirect;

                try validateTypeIndex(immediates.type_index, module);
                try validateTableIndex(immediates.table_index, module);

                try self.popType(.I32);

                try Helpers.popPushFuncTypes(self, immediates.type_index, module);
            },
            .Select => {
                try self.popType(.I32);
                const valtype1_or_null: ?ValType = try self.popAnyType();
                const valtype2_or_null: ?ValType = try self.popAnyType();
                if (valtype1_or_null == null) {
                    try self.pushType(valtype2_or_null);
                } else if (valtype2_or_null == null) {
                    try self.pushType(valtype1_or_null);
                } else {
                    const valtype1 = valtype1_or_null.?;
                    const valtype2 = valtype2_or_null.?;
                    if (valtype1 != valtype2) {
                        return error.ValidationTypeMismatch;
                    }
                    if (valtype1.isRefType()) {
                        return error.ValidationTypeMustBeNumeric;
                    }
                    try self.pushType(valtype1);
                }
            },
            .Select_T => {
                const valtype: ValType = instruction.immediate.ValType;
                try self.popType(.I32);
                try self.popType(valtype);
                try self.popType(valtype);
                try self.pushType(valtype);
            },
            .Local_Get => {
                const valtype = try Helpers.getLocalValtype(self, module, func, instruction.immediate.Index);
                try self.pushType(valtype);
            },
            .Local_Set => {
                const valtype = try Helpers.getLocalValtype(self, module, func, instruction.immediate.Index);
                try self.popType(valtype);
            },
            .Local_Tee => {
                const valtype = try Helpers.getLocalValtype(self, module, func, instruction.immediate.Index);
                try self.popType(valtype);
                try self.pushType(valtype);
            },
            .Global_Get => {
                const valtype = try Helpers.getGlobalValtype(module, instruction.immediate.Index, .None);
                try self.pushType(valtype);
            },
            .Global_Set => {
                const valtype = try Helpers.getGlobalValtype(module, instruction.immediate.Index, .Mutable);
                try self.popType(valtype);
            },
            .Table_Get => {
                const reftype = try getTableReftype(module, instruction.immediate.Index);
                try self.popType(.I32);
                try self.pushType(reftype);
            },
            .Table_Set => {
                const reftype = try getTableReftype(module, instruction.immediate.Index);
                try self.popType(reftype);
                try self.popType(.I32);
            },
            .I32_Load, .I32_Load8_S, .I32_Load8_U, .I32_Load16_S, .I32_Load16_U => {
                try self.popType(.I32);
                try validateMemoryIndex(module);
                try self.pushType(.I32);
            },
            .I64_Load, .I64_Load8_S, .I64_Load8_U, .I64_Load16_S, .I64_Load16_U, .I64_Load32_S, .I64_Load32_U => {
                try self.popType(.I32);
                try validateMemoryIndex(module);
                try self.pushType(.I64);
            },
            .F32_Load => {
                try self.popType(.I32);
                try validateMemoryIndex(module);
                try self.pushType(.F32);
            },
            .F64_Load => {
                try self.popType(.I32);
                try validateMemoryIndex(module);
                try self.pushType(.F64);
            },
            .I32_Store, .I32_Store8, .I32_Store16 => {
                try Helpers.validateStoreOp(self, module, .I32);
            },
            .I64_Store, .I64_Store8, .I64_Store16, .I64_Store32 => {
                try Helpers.validateStoreOp(self, module, .I64);
            },
            .F32_Store => {
                try Helpers.validateStoreOp(self, module, .F32);
            },
            .F64_Store => {
                try Helpers.validateStoreOp(self, module, .F64);
            },
            .Memory_Size => {
                try validateMemoryIndex(module);
                try self.pushType(.I32);
            },
            .Memory_Grow => {
                try validateMemoryIndex(module);
                try self.popType(.I32);
                try self.pushType(.I32);
            },
            .I32_Const => {
                try self.pushType(.I32);
            },
            .I64_Const => {
                try self.pushType(.I64);
            },
            .F32_Const => {
                try self.pushType(.F32);
            },
            .F64_Const => {
                try self.pushType(.F64);
            },
            .I32_Eqz, .I32_Clz, .I32_Ctz, .I32_Popcnt => {
                try Helpers.validateNumericUnaryOp(self, .I32, .I32);
            },
            .I32_Eq, .I32_NE, .I32_LT_S, .I32_LT_U, .I32_GT_S, .I32_GT_U, .I32_LE_S, .I32_LE_U, .I32_GE_S, .I32_GE_U, .I32_Add, .I32_Sub, .I32_Mul, .I32_Div_S, .I32_Div_U, .I32_Rem_S, .I32_Rem_U, .I32_And, .I32_Or, .I32_Xor, .I32_Shl, .I32_Shr_S, .I32_Shr_U, .I32_Rotl, .I32_Rotr => {
                try Helpers.validateNumericBinaryOp(self, .I32, .I32);
            },
            .I64_Clz, .I64_Ctz, .I64_Popcnt => {
                try Helpers.validateNumericUnaryOp(self, .I64, .I64);
            },
            .I64_Eqz => {
                try Helpers.validateNumericUnaryOp(self, .I64, .I32);
            },
            .I64_Eq, .I64_NE, .I64_LT_S, .I64_LT_U, .I64_GT_S, .I64_GT_U, .I64_LE_S, .I64_LE_U, .I64_GE_S, .I64_GE_U => {
                try Helpers.validateNumericBinaryOp(self, .I64, .I32);
            },
            .I64_Add, .I64_Sub, .I64_Mul, .I64_Div_S, .I64_Div_U, .I64_Rem_S, .I64_Rem_U, .I64_And, .I64_Or, .I64_Xor, .I64_Shl, .I64_Shr_S, .I64_Shr_U, .I64_Rotl, .I64_Rotr => {
                try Helpers.validateNumericBinaryOp(self, .I64, .I64);
            },
            .F32_EQ, .F32_NE, .F32_LT, .F32_GT, .F32_LE, .F32_GE => {
                try Helpers.validateNumericBinaryOp(self, .F32, .I32);
            },
            .F32_Add, .F32_Sub, .F32_Mul, .F32_Div, .F32_Min, .F32_Max, .F32_Copysign => {
                try Helpers.validateNumericBinaryOp(self, .F32, .F32);
            },
            .F32_Abs, .F32_Neg, .F32_Ceil, .F32_Floor, .F32_Trunc, .F32_Nearest, .F32_Sqrt => {
                try Helpers.validateNumericUnaryOp(self, .F32, .F32);
            },
            .F64_Abs, .F64_Neg, .F64_Ceil, .F64_Floor, .F64_Trunc, .F64_Nearest, .F64_Sqrt => {
                try Helpers.validateNumericUnaryOp(self, .F64, .F64);
            },
            .F64_EQ, .F64_NE, .F64_LT, .F64_GT, .F64_LE, .F64_GE => {
                try Helpers.validateNumericBinaryOp(self, .F64, .I32);
            },
            .F64_Add, .F64_Sub, .F64_Mul, .F64_Div, .F64_Min, .F64_Max, .F64_Copysign => {
                try Helpers.validateNumericBinaryOp(self, .F64, .F64);
            },
            .I32_Wrap_I64 => {
                try Helpers.validateNumericUnaryOp(self, .I64, .I32);
            },
            .I32_Trunc_F32_S, .I32_Trunc_F32_U => {
                try Helpers.validateNumericUnaryOp(self, .F32, .I32);
            },
            .I32_Trunc_F64_S, .I32_Trunc_F64_U => {
                try Helpers.validateNumericUnaryOp(self, .F64, .I32);
            },
            .I64_Extend_I32_S, .I64_Extend_I32_U => {
                try Helpers.validateNumericUnaryOp(self, .I32, .I64);
            },
            .I64_Trunc_F32_S, .I64_Trunc_F32_U => {
                try Helpers.validateNumericUnaryOp(self, .F32, .I64);
            },
            .I64_Trunc_F64_S, .I64_Trunc_F64_U => {
                try Helpers.validateNumericUnaryOp(self, .F64, .I64);
            },
            .F32_Convert_I32_S, .F32_Convert_I32_U => {
                try Helpers.validateNumericUnaryOp(self, .I32, .F32);
            },
            .F32_Convert_I64_S, .F32_Convert_I64_U => {
                try Helpers.validateNumericUnaryOp(self, .I64, .F32);
            },
            .F32_Demote_F64 => {
                try Helpers.validateNumericUnaryOp(self, .F64, .F32);
            },
            .F64_Convert_I32_S, .F64_Convert_I32_U => {
                try Helpers.validateNumericUnaryOp(self, .I32, .F64);
            },
            .F64_Convert_I64_S, .F64_Convert_I64_U => {
                try Helpers.validateNumericUnaryOp(self, .I64, .F64);
            },
            .F64_Promote_F32 => {
                try Helpers.validateNumericUnaryOp(self, .F32, .F64);
            },
            .I32_Reinterpret_F32 => {
                try Helpers.validateNumericUnaryOp(self, .F32, .I32);
            },
            .I64_Reinterpret_F64 => {
                try Helpers.validateNumericUnaryOp(self, .F64, .I64);
            },
            .F32_Reinterpret_I32 => {
                try Helpers.validateNumericUnaryOp(self, .I32, .F32);
            },
            .F64_Reinterpret_I64 => {
                try Helpers.validateNumericUnaryOp(self, .I64, .F64);
            },
            .I32_Extend8_S, .I32_Extend16_S => {
                try Helpers.validateNumericUnaryOp(self, .I32, .I32);
            },
            .I64_Extend8_S, .I64_Extend16_S, .I64_Extend32_S => {
                try Helpers.validateNumericUnaryOp(self, .I64, .I64);
            },
            .Ref_Null => {
                try self.pushType(instruction.immediate.ValType);
            },
            .Ref_Is_Null => {
                var valtype_or_null: ?ValType = try self.popAnyType();
                if (valtype_or_null) |valtype| {
                    if (valtype.isRefType() == false) {
                        return error.ValidationTypeMismatch;
                    }
                }
                try self.pushType(.I32);
            },
            .Ref_Func => {
                const func_index: u32 = instruction.immediate.Index;
                try validateFunctionIndex(func_index, module);

                const is_referencing_current_function: bool = module.imports.functions.items.len <= func_index and
                    &module.functions.items[func_index - module.imports.functions.items.len] == func;

                // references to the current function must be declared in element segments
                if (is_referencing_current_function) {
                    var needs_declaration: bool = true;
                    skip_outer: for (module.elements.items) |elem_def| {
                        if (elem_def.mode == .Declarative and elem_def.reftype == .FuncRef) {
                            if (elem_def.elems_value.items.len > 0) {
                                for (elem_def.elems_value.items) |val| {
                                    if (val.FuncRef.index == func_index) {
                                        needs_declaration = false;
                                        break :skip_outer;
                                    }
                                }
                            } else {
                                for (elem_def.elems_expr.items) |expr| {
                                    if (std.meta.activeTag(expr) == .Value) {
                                        if (expr.Value.FuncRef.index == func_index) {
                                            needs_declaration = false;
                                            break :skip_outer;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (needs_declaration) {
                        return error.ValidationFuncRefUndeclared;
                    }
                }

                try self.pushType(.FuncRef);
            },
            .I32_Trunc_Sat_F32_S, .I32_Trunc_Sat_F32_U => {
                try Helpers.validateNumericUnaryOp(self, .F32, .I32);
            },
            .I32_Trunc_Sat_F64_S, .I32_Trunc_Sat_F64_U => {
                try Helpers.validateNumericUnaryOp(self, .F64, .I32);
            },
            .I64_Trunc_Sat_F32_S, .I64_Trunc_Sat_F32_U => {
                try Helpers.validateNumericUnaryOp(self, .F32, .I64);
            },
            .I64_Trunc_Sat_F64_S, .I64_Trunc_Sat_F64_U => {
                try Helpers.validateNumericUnaryOp(self, .F64, .I64);
            },
            .Memory_Init => {
                try validateMemoryIndex(module);
                try validateDataIndex(instruction.immediate.Index, module);
                try self.popType(.I32);
                try self.popType(.I32);
                try self.popType(.I32);
            },
            .Data_Drop => {
                if (module.data_count != null) {
                    try validateDataIndex(instruction.immediate.Index, module);
                } else {
                    return error.MalformedMissingDataCountSection;
                }
            },
            .Memory_Copy, .Memory_Fill => {
                try validateMemoryIndex(module);
                try self.popType(.I32);
                try self.popType(.I32);
                try self.popType(.I32);
            },
            .Table_Init => {
                const pair: TablePairImmediates = instruction.immediate.TablePair;
                const elem_index = pair.index_x;
                const table_index = pair.index_y;
                try validateTableIndex(table_index, module);
                try validateElementIndex(elem_index, module);

                const elem_reftype: ValType = module.elements.items[elem_index].reftype;
                const table_reftype: ValType = module.tables.items[table_index].reftype;

                if (elem_reftype != table_reftype) {
                    return error.ValidationTypeMismatch;
                }

                try self.popType(.I32);
                try self.popType(.I32);
                try self.popType(.I32);
            },
            .Elem_Drop => {
                try validateElementIndex(instruction.immediate.Index, module);
            },
            .Table_Copy => {
                const pair: TablePairImmediates = instruction.immediate.TablePair;
                const dest_table_index = pair.index_x;
                const src_table_index = pair.index_y;
                try validateTableIndex(dest_table_index, module);
                try validateTableIndex(src_table_index, module);

                const dest_reftype: ValType = module.tables.items[dest_table_index].reftype;
                const src_reftype: ValType = module.tables.items[src_table_index].reftype;

                if (dest_reftype != src_reftype) {
                    return error.ValidationTypeMismatch;
                }

                try self.popType(.I32);
                try self.popType(.I32);
                try self.popType(.I32);
            },
            .Table_Grow => {
                try validateTableIndex(instruction.immediate.Index, module);

                try self.popType(.I32);
                if (try self.popAnyType()) |init_type| {
                    var table_reftype: ValType = try getTableReftype(module, instruction.immediate.Index);
                    if (init_type != table_reftype) {
                        return error.ValidationTypeMismatch;
                    }
                }

                try self.pushType(.I32);
            },
            .Table_Size => {
                try validateTableIndex(instruction.immediate.Index, module);
                try self.pushType(.I32);
            },
            .Table_Fill => {
                try validateTableIndex(instruction.immediate.Index, module);
                try self.popType(.I32);
                if (try self.popAnyType()) |valtype| {
                    var table_reftype: ValType = try getTableReftype(module, instruction.immediate.Index);
                    if (valtype != table_reftype) {
                        return error.ValidationTypeMismatch;
                    }
                }
                try self.popType(.I32);
            },
        }
    }

    fn endValidateCode(self: *ModuleValidator) !void {
        try self.type_stack.resize(0);
        try self.control_stack.resize(0);
        try self.control_types.resize(0);
    }

    fn pushType(self: *ModuleValidator, valtype: ?ValType) !void {
        try self.type_stack.append(valtype);
    }

    fn popAnyType(self: *ModuleValidator) !?ValType {
        const top_frame: *const ControlFrame = &self.control_stack.items[self.control_stack.items.len - 1];
        const types: []?ValType = self.type_stack.items;

        if (top_frame.is_unreachable and types.len == top_frame.types_stack_height) {
            return null;
        }

        if (self.type_stack.items.len <= top_frame.types_stack_height) {
            return error.ValidationTypeMismatch;
        }
        return self.type_stack.pop();
    }

    fn popType(self: *ModuleValidator, expected_or_null: ?ValType) !void {
        const valtype_or_null = try self.popAnyType();
        if (valtype_or_null != expected_or_null and valtype_or_null != null and expected_or_null != null) {
            return error.ValidationTypeMismatch;
        }
    }

    fn pushControl(self: *ModuleValidator, opcode: Opcode, start_types: []const ValType, end_types: []const ValType) !void {
        const control_types_start_index: usize = self.control_types.items.len;
        try self.control_types.appendSlice(start_types);
        var control_start_types: []const ValType = self.control_types.items[control_types_start_index..self.control_types.items.len];

        const control_types_end_index: usize = self.control_types.items.len;
        try self.control_types.appendSlice(end_types);
        var control_end_types: []const ValType = self.control_types.items[control_types_end_index..self.control_types.items.len];

        try self.control_stack.append(ControlFrame{
            .opcode = opcode,
            .start_types = control_start_types,
            .end_types = control_end_types,
            .types_stack_height = self.type_stack.items.len,
            .is_function = true,
            .is_unreachable = false,
        });

        if (opcode != .Call) {
            for (start_types) |valtype| {
                try self.pushType(valtype);
            }
        }
    }

    fn popControl(self: *ModuleValidator) !ControlFrame {
        const frame: *const ControlFrame = &self.control_stack.items[self.control_stack.items.len - 1];

        var i = frame.end_types.len;
        while (i > 0) : (i -= 1) {
            if (frame.is_unreachable and self.type_stack.items.len == frame.types_stack_height) {
                break;
            }
            try self.popType(frame.end_types[i - 1]);
        }

        if (self.type_stack.items.len != frame.types_stack_height) {
            return error.ValidationTypeStackHeightMismatch;
        }

        _ = self.control_stack.pop();

        return frame.*;
    }

    fn freeControlTypes(self: *ModuleValidator, frame: *const ControlFrame) !void {
        var num_used_types: usize = frame.start_types.len + frame.end_types.len;
        try self.control_types.resize(self.control_types.items.len - num_used_types);
    }
};

// new idea:
// embed immediates with the opcodes in a stream of opaque data. each opcode knows how much data it uses and
// increments the program counter by that amount. so it would look something like this:
// op1
// op1 immediate
// op2 (no immediate)
// op3
// op3 imm1
// op3 imm2
// op3 imm3
//
// this way the opcode and immediate data is all in cache in the same stream, but there are no wasted bytes
// due to union padding.
// could experiment with adding alignment padding later

// const InstructionFunc = *const fn (pc: u32, code: [*]const u8, stack: *Stack) anyerror!void;

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
        &op_Noop,
        &op_Block,
        &op_Loop,
        &op_If,
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
    };

    fn run(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc].opcode), .{ pc, code, stack });
    }

    fn lookup(opcode: Opcode) InstructionFunc {
        return opcodeToFuncTable[@enumToInt(opcode)];
    }

    const OpHelpers = struct {
        fn propagateNanWithOp(op: anytype, v1: anytype, v2: @TypeOf(v1)) @TypeOf(v1) {
            if (std.math.isNan(v1)) {
                return v1;
            } else if (std.math.isNan(v2)) {
                return v2;
            } else {
                return op(v1, v2);
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

            var truncated = @trunc(value);

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
            return @floatToInt(T, truncated);
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

            var truncated = @trunc(value);

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
            return @floatToInt(T, truncated);
        }

        fn loadFromMem(comptime T: type, store: *Store, offset_from_memarg: usize, offset_from_stack: i32) !T {
            if (offset_from_stack < 0) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const memory: *const MemoryInstance = store.getMemory(0);
            const offset: usize = offset_from_memarg + @intCast(usize, offset_from_stack);

            const bit_count = std.meta.bitCount(T);
            const read_type = switch (bit_count) {
                8 => u8,
                16 => u16,
                32 => u32,
                64 => u64,
                else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
            };

            const end = offset + (bit_count / 8);

            if (memory.mem.items.len < end) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const mem = memory.mem.items[offset..end];
            const value = std.mem.readIntSliceLittle(read_type, mem);
            return @bitCast(T, value);
        }

        fn storeInMem(value: anytype, store: *Store, offset_from_memarg: usize, offset_from_stack: i32) !void {
            if (offset_from_stack < 0) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const memory: *MemoryInstance = store.getMemory(0);
            const offset: usize = offset_from_memarg + @intCast(u32, offset_from_stack);

            const bit_count = std.meta.bitCount(@TypeOf(value));
            const write_type = switch (bit_count) {
                8 => u8,
                16 => u16,
                32 => u32,
                64 => u64,
                else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
            };

            const end = offset + (bit_count / 8);
            if (memory.mem.items.len < end) {
                return error.TrapOutOfBoundsMemoryAccess;
            }

            const write_value = @bitCast(write_type, value);

            const mem = memory.mem.items[offset..end];
            std.mem.writeIntSliceLittle(write_type, mem, write_value);
        }

        fn call(pc: u32, stack: *Stack, module_instance: *ModuleInstance, func: *const FunctionInstance) !FuncCallData {
            const functype: *const FunctionTypeDefinition = &module_instance.module_def.types.items[func.type_def_index];
            const param_types: []const ValType = functype.getParams();
            const return_types: []const ValType = functype.getReturns();
            const continuation: u32 = pc + 1;

            try stack.pushFrame(func, module_instance, param_types, func.local_types.items);
            try stack.pushLabel(@intCast(u32, return_types.len), continuation);

            return FuncCallData{
                .code = module_instance.module_def.code.instructions.items.ptr,
                .continuation = func.offset_into_instructions,
            };
        }

        fn callImport(pc: u32, stack: *Stack, func: *const FunctionImport) !FuncCallData {
            switch (func.data) {
                .Host => |data| {
                    const params_len: u32 = @intCast(u32, data.func_def.getParams().len);
                    const returns_len: u32 = @intCast(u32, data.func_def.getReturns().len);

                    if (stack.num_values + returns_len < stack.values.len) {
                        var params = stack.values[stack.num_values - params_len .. stack.num_values];
                        var returns_temp = stack.values[stack.num_values .. stack.num_values + returns_len];

                        data.callback(data.userdata, params, returns_temp);

                        stack.num_values = (stack.num_values - params_len) + returns_len;
                        var returns_dest = stack.values[stack.num_values - returns_len .. stack.num_values];

                        std.mem.copy(Val, returns_dest, returns_temp);

                        return FuncCallData{
                            .code = stack.topFrame().module_instance.module_def.code.instructions.items.ptr,
                            .continuation = pc + 1,
                        };
                    } else {
                        return error.TrapStackExhausted;
                    }
                },
                .Wasm => |data| {
                    const func_instance: *const FunctionInstance = &data.module_instance.store.functions.items[data.index];
                    return try call(pc, stack, data.module_instance, func_instance);
                },
            }
        }

        fn branch(stack: *Stack, label_id: u32) ?FuncCallData {
            const label: *const Label = stack.findLabel(@intCast(u32, label_id));
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
    };

    fn debugPreamble(name: []const u8, pc: u32, code: [*]const Instruction, stack: *Stack) void {
        // std.debug.print("\tinstruction: {s} ({}) at {} with code {*} ({*}).\n", .{ name, code[pc].opcode, pc, code, stack.topFrame().module_instance });
        _ = name;
        _ = pc;
        _ = code;
        _ = stack;
    }

    fn op_Invalid(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        _ = pc;
        _ = code;
        _ = stack;
        unreachable;
    }

    fn op_Unreachable(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        _ = pc;
        _ = code;
        _ = stack;
        return error.TrapUnreachable;
    }

    fn op_Noop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Noop", pc, code, stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Block(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Block", pc, code, stack);
        try stack.pushLabel(code[pc].immediate.Block.num_returns, code[pc].immediate.Block.continuation);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Loop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Loop", pc, code, stack);
        try stack.pushLabel(code[pc].immediate.Block.num_returns, code[pc].immediate.Block.continuation);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_If(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("If", pc, code, stack);
        var next_pc: u32 = undefined;

        const condition = try stack.popI32();
        if (condition != 0) {
            try stack.pushLabel(code[pc].immediate.Block.num_returns, code[pc].immediate.Block.continuation);
            next_pc = pc + 1;
        } else if (stack.topFrame().module_instance.module_def.if_to_else_offsets.get(pc)) |else_offset| {
            try stack.pushLabel(code[pc].immediate.Block.num_returns, code[pc].immediate.Block.continuation);
            // +1 to skip the else opcode, since it's treated as an End for the If block.
            next_pc = else_offset + 1;
        } else {
            next_pc = code[pc].immediate.Block.continuation + 1;
        }

        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[next_pc].opcode), .{ next_pc, code, stack });
    }

    fn op_Else(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Else", pc, code, stack);
        // getting here means we reached the end of the if opcode chain, so skip to the true end opcode
        var next_pc: u32 = code[pc].immediate.Block.continuation;
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[next_pc].opcode), .{ next_pc, code, stack });
    }

    fn op_End(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("End", pc, code, stack);

        // TODO - this instruction tries to determine at runtime what behavior to take, but we can
        // probably determine this in the decode phase and split into 3 different end instructions
        // to avoid branching. Probably could bake the return types length into the immediate to avoid
        // cache misses on the lookup we're currently doing.

        var next: FuncCallData = undefined;

        // determine if this is a a scope or function call exit
        const top_label: *const Label = stack.topLabel();
        const frame_label: *const Label = stack.frameLabel();
        if (top_label != frame_label) {
            // Since the only values on the stack should be the returns from the block, we just pop the
            // label, which leaves the value stack alone.
            stack.popLabel();

            next = FuncCallData{
                .continuation = pc + 1,
                .code = code,
            };
        } else {
            next = stack.popFrame() orelse return;
        }

        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Branch(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Branch", pc, code, stack);
        const label_id: u32 = code[pc].immediate.LabelId;
        const next: FuncCallData = OpHelpers.branch(stack, label_id) orelse return;
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Branch_If(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Branch_If", pc, code, stack);
        var next: FuncCallData = undefined;
        const v = try stack.popI32();
        if (v != 0) {
            const label_id: u32 = code[pc].immediate.LabelId;
            next = OpHelpers.branch(stack, label_id) orelse return;
        } else {
            next = FuncCallData{
                .code = code,
                .continuation = pc + 1,
            };
        }
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Branch_Table(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table", pc, code, stack);
        const immediates: *const BranchTableImmediates = &stack.topFrame().module_instance.module_def.code.branch_table.items[code[pc].immediate.Index];
        const table: []const u32 = immediates.label_ids.items;

        const label_index = try stack.popI32();
        const label_id: u32 = if (label_index >= 0 and label_index < table.len) table[@intCast(usize, label_index)] else immediates.fallback_id;
        const next: FuncCallData = OpHelpers.branch(stack, label_id) orelse return;

        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Return(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Return", pc, code, stack);
        var next: FuncCallData = stack.popFrame() orelse return;
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Call(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Call", pc, code, stack);

        const func_index: u32 = code[pc].immediate.Index;
        const module_instance: *ModuleInstance = stack.topFrame().module_instance;
        const store: *const Store = &module_instance.store;

        var next: FuncCallData = undefined;
        if (func_index >= store.imports.functions.items.len) {
            const func_instance_index = func_index - store.imports.functions.items.len;
            const func: *const FunctionInstance = &store.functions.items[@intCast(usize, func_instance_index)];
            next = try OpHelpers.call(pc, stack, module_instance, func);
        } else {
            var func_import = &store.imports.functions.items[func_index];
            next = try OpHelpers.callImport(pc, stack, func_import);
        }

        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Call_Indirect(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Call_Indirect", pc, code, stack);

        const current_module: *ModuleInstance = stack.topFrame().module_instance;
        const immediates: *const CallIndirectImmediates = &code[pc].immediate.CallIndirect;
        const table_index: u32 = immediates.table_index;

        const table: *const TableInstance = current_module.store.getTable(table_index);

        const ref_index = try stack.popI32();
        if (table.refs.items.len <= ref_index or ref_index < 0) {
            return error.TrapUndefinedElement;
        }

        const ref: Val = table.refs.items[@intCast(usize, ref_index)];
        if (ref.isNull()) {
            return error.TrapUninitializedElement;
        }

        const func_index = ref.FuncRef.index;

        var call_module: *ModuleInstance = ref.FuncRef.module_instance;
        var call_store = &call_module.store;

        std.debug.assert(call_module != &empty_module_instance); // Should have been set in module instantiation

        var next: FuncCallData = undefined;
        if (func_index >= call_store.imports.functions.items.len) {
            const func: *const FunctionInstance = &call_store.functions.items[func_index - call_store.imports.functions.items.len];
            if (func.type_def_index != immediates.type_index) {
                const func_type_def: *const FunctionTypeDefinition = &call_module.module_def.types.items[func.type_def_index];
                const immediate_type_def: *const FunctionTypeDefinition = &call_module.module_def.types.items[immediates.type_index];

                var type_comparer = FunctionTypeContext{};
                if (type_comparer.eql(func_type_def, immediate_type_def) == false) {
                    return error.TrapIndirectCallTypeMismatch;
                }
            }
            next = try OpHelpers.call(pc, stack, call_module, func);
        } else {
            var func_import: *const FunctionImport = &call_store.imports.functions.items[func_index];
            var func_type_def: *const FunctionTypeDefinition = &call_module.module_def.types.items[immediates.type_index];
            if (func_import.isTypeSignatureEql(func_type_def) == false) {
                return error.TrapIndirectCallTypeMismatch;
            }
            next = try OpHelpers.callImport(pc, stack, func_import);
        }

        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(next.code[next.continuation].opcode), .{ next.continuation, next.code, stack });
    }

    fn op_Drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Drop", pc, code, stack);
        _ = try stack.popValue();
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Select(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Select", pc, code, stack);

        var boolean: i32 = try stack.popI32();
        var v2: Val = try stack.popValue();
        var v1: Val = try stack.popValue();

        if (boolean != 0) {
            try stack.pushValue(v1);
        } else {
            try stack.pushValue(v2);
        }

        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Select_T(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Select_T", pc, code, stack);

        var boolean: i32 = try stack.popI32();
        var v2: Val = try stack.popValue();
        var v1: Val = try stack.popValue();

        if (boolean != 0) {
            try stack.pushValue(v1);
        } else {
            try stack.pushValue(v2);
        }

        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Local_Get(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Local_Get", pc, code, stack);

        var locals_index: u32 = code[pc].immediate.Index;
        var frame: *const CallFrame = stack.topFrame();
        var v: Val = frame.locals[locals_index];
        try stack.pushValue(v);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Local_Set(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Local_Set", pc, code, stack);
        var locals_index: u32 = code[pc].immediate.Index;
        var frame: *CallFrame = stack.topFrame();
        var v: Val = try stack.popValue();
        frame.locals[locals_index] = v;
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Local_Tee(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Local_Tee", pc, code, stack);
        var locals_index: u32 = code[pc].immediate.Index;
        var frame: *CallFrame = stack.topFrame();
        var v: Val = try stack.topValue();
        frame.locals[locals_index] = v;
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Global_Get(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Global_Get", pc, code, stack);
        var global_index: u32 = code[pc].immediate.Index;
        var global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        try stack.pushValue(global.value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Global_Set(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Global_Set", pc, code, stack);
        var global_index: u32 = code[pc].immediate.Index;
        var global: *GlobalInstance = stack.topFrame().module_instance.store.getGlobal(global_index);
        global.value = try stack.popValue();
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Get(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table_Get", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        const table: *const TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const index: i32 = try stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        const ref = table.refs.items[@intCast(usize, index)];
        try stack.pushValue(ref);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Set(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table_Set", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        var table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const ref = try stack.popValue();
        const index: i32 = try stack.popI32();
        if (table.refs.items.len <= index or index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (ref.isRefType() == false) {
            return error.TrapTableSetTypeMismatch;
        }
        table.refs.items[@intCast(usize, index)] = ref;
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Load", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value = try OpHelpers.loadFromMem(i32, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Load", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value = try OpHelpers.loadFromMem(i64, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Load", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value = try OpHelpers.loadFromMem(f32, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Load(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Load", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value = try OpHelpers.loadFromMem(f64, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Load8_S", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: i32 = try OpHelpers.loadFromMem(i8, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Load8_U", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: u32 = try OpHelpers.loadFromMem(u8, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI32(@bitCast(i32, value));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Load16_S", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: i32 = try OpHelpers.loadFromMem(i16, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Load16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Load16_U", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: u32 = try OpHelpers.loadFromMem(u16, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI32(@bitCast(i32, value));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Load8_S", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: i64 = try OpHelpers.loadFromMem(i8, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load8_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Load8_U", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: u64 = try OpHelpers.loadFromMem(u8, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI64(@bitCast(i64, value));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Load16_S", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: i64 = try OpHelpers.loadFromMem(i16, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load16_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Load16_U", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: u64 = try OpHelpers.loadFromMem(u16, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI64(@bitCast(i64, value));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Load32_S", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: i64 = try OpHelpers.loadFromMem(i32, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Load32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Load32_U", pc, code, stack);
        var offset_from_stack: i32 = try stack.popI32();
        var value: u64 = try OpHelpers.loadFromMem(u32, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try stack.pushI64(@bitCast(i64, value));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Store", pc, code, stack);
        const value: i32 = try stack.popI32();
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Store", pc, code, stack);
        const value: i64 = try stack.popI64();
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Store", pc, code, stack);
        const value: f32 = try stack.popF32();
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Store(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Store", pc, code, stack);
        const value: f64 = try stack.popF64();
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Store8(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Store8", pc, code, stack);
        const value: i8 = @truncate(i8, try stack.popI32());
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Store16(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Store16", pc, code, stack);
        const value: i16 = @truncate(i16, try stack.popI32());
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store8(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Store8", pc, code, stack);
        const value: i8 = @truncate(i8, try stack.popI64());
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store16(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Store16", pc, code, stack);
        const value: i16 = @truncate(i16, try stack.popI64());
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Store32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Store32", pc, code, stack);
        const value: i32 = @truncate(i32, try stack.popI64());
        const offset_from_stack: i32 = try stack.popI32();
        try OpHelpers.storeInMem(value, &stack.topFrame().module_instance.store, code[pc].immediate.MemoryOffset, offset_from_stack);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Size(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Memory_Size", pc, code, stack);
        const memory_index: usize = 0;
        var memory_instance: *const MemoryInstance = stack.topFrame().module_instance.store.getMemory(memory_index);

        const num_pages: i32 = @intCast(i32, memory_instance.size());
        try stack.pushI32(num_pages);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Grow(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Memory_Grow", pc, code, stack);
        const memory_index: usize = 0;
        var memory_instance: *MemoryInstance = stack.topFrame().module_instance.store.getMemory(memory_index);

        const old_num_pages: i32 = @intCast(i32, memory_instance.limits.min);
        const num_pages: i32 = try stack.popI32();

        if (num_pages >= 0 and memory_instance.grow(@intCast(usize, num_pages))) {
            try stack.pushI32(old_num_pages);
            try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
        } else {
            try stack.pushI32(-1);
            try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
        }
    }

    fn op_I32_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Const", pc, code, stack);
        var v: i32 = code[pc].immediate.ValueI32;
        try stack.pushI32(v);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Const", pc, code, stack);
        var v: i64 = code[pc].immediate.ValueI64;
        try stack.pushI64(v);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Const", pc, code, stack);
        var v: f32 = code[pc].immediate.ValueF32;
        try stack.pushF32(v);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Const(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Const", pc, code, stack);
        var v: f64 = code[pc].immediate.ValueF64;
        try stack.pushF64(v);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Eqz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Eqz", pc, code, stack);
        var v1: i32 = try stack.popI32();
        var result: i32 = if (v1 == 0) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Eq(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Eq", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result: i32 = if (v1 == v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_NE", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result: i32 = if (v1 != v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_LT_S", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result: i32 = if (v1 < v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_LT_U", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var result: i32 = if (v1 < v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_GT_S", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result: i32 = if (v1 > v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_GT_U", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var result: i32 = if (v1 > v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_LE_S", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result: i32 = if (v1 <= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_LE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_LE_U", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var result: i32 = if (v1 <= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_GE_S", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result: i32 = if (v1 >= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_GE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_GE_U", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var result: i32 = if (v1 >= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Eqz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Eqz", pc, code, stack);
        var v1: i64 = try stack.popI64();
        var result: i32 = if (v1 == 0) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Eq(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Eq", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result: i32 = if (v1 == v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_NE", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result: i32 = if (v1 != v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_LT_S", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result: i32 = if (v1 < v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_LT_U", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var result: i32 = if (v1 < v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GT_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_GT_S", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result: i32 = if (v1 > v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GT_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_GT_U", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var result: i32 = if (v1 > v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_LE_S", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result: i32 = if (v1 <= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_LE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_LE_U", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var result: i32 = if (v1 <= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GE_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_GE_S", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result: i32 = if (v1 >= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_GE_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_GE_U", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var result: i32 = if (v1 >= v2) 1 else 0;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_EQ", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value: i32 = if (v1 == v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_NE", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value: i32 = if (v1 != v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_LT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_LT", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value: i32 = if (v1 < v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_GT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_GT", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value: i32 = if (v1 > v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_LE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_LE", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value: i32 = if (v1 <= v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_GE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_GE", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value: i32 = if (v1 >= v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_EQ(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_EQ", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value: i32 = if (v1 == v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_NE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_NE", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value: i32 = if (v1 != v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_LT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_LT", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value: i32 = if (v1 < v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_GT(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_GT", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value: i32 = if (v1 > v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_LE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_LE", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value: i32 = if (v1 <= v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_GE(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_GE", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value: i32 = if (v1 >= v2) 1 else 0;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Clz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Clz", pc, code, stack);
        var v: i32 = try stack.popI32();
        var num_zeroes = @clz(v);
        try stack.pushI32(num_zeroes);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Ctz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Ctz", pc, code, stack);
        var v: i32 = try stack.popI32();
        var num_zeroes = @ctz(v);
        try stack.pushI32(num_zeroes);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Popcnt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Popcnt", pc, code, stack);
        var v: i32 = try stack.popI32();
        var num_bits_set = @popCount(v);
        try stack.pushI32(num_bits_set);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Add", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result = v1 +% v2;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Sub", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var result = v1 -% v2;
        try stack.pushI32(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Mul", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var value = v1 *% v2;
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Div_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Div_S", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var value = std.math.divTrunc(i32, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Div_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Div_U", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var value_unsigned = std.math.divFloor(u32, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        var value = @bitCast(i32, value_unsigned);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rem_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Rem_S", pc, code, stack);
        var v2: i32 = try stack.popI32();
        var v1: i32 = try stack.popI32();
        var denom = try std.math.absInt(v2);
        var value = std.math.rem(i32, v1, denom) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rem_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Rem_U", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var value_unsigned = std.math.rem(u32, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        var value = @bitCast(i32, value_unsigned);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_And(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_And", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var value = @bitCast(i32, v1 & v2);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Or(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Or", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var value = @bitCast(i32, v1 | v2);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Xor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Xor", pc, code, stack);
        var v2: u32 = @bitCast(u32, try stack.popI32());
        var v1: u32 = @bitCast(u32, try stack.popI32());
        var value = @bitCast(i32, v1 ^ v2);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Shl", pc, code, stack);
        var shift_unsafe: i32 = try stack.popI32();
        var int: i32 = try stack.popI32();
        var shift: i32 = try std.math.mod(i32, shift_unsafe, 32);
        var value = std.math.shl(i32, int, shift);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Shr_S", pc, code, stack);
        var shift_unsafe: i32 = try stack.popI32();
        var int: i32 = try stack.popI32();
        var shift = try std.math.mod(i32, shift_unsafe, 32);
        var value = std.math.shr(i32, int, shift);
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Shr_U", pc, code, stack);
        var shift_unsafe: u32 = @bitCast(u32, try stack.popI32());
        var int: u32 = @bitCast(u32, try stack.popI32());
        var shift = try std.math.mod(u32, shift_unsafe, 32);
        var value = @bitCast(i32, std.math.shr(u32, int, shift));
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rotl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Rotl", pc, code, stack);
        var rot: u32 = @bitCast(u32, try stack.popI32());
        var int: u32 = @bitCast(u32, try stack.popI32());
        var value = @bitCast(i32, std.math.rotl(u32, int, rot));
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Rotr(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Rotr", pc, code, stack);
        var rot: u32 = @bitCast(u32, try stack.popI32());
        var int: u32 = @bitCast(u32, try stack.popI32());
        var value = @bitCast(i32, std.math.rotr(u32, int, rot));
        try stack.pushI32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Clz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Clz", pc, code, stack);
        var v: i64 = try stack.popI64();
        var num_zeroes = @clz(v);
        try stack.pushI64(num_zeroes);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Ctz(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Ctz", pc, code, stack);
        var v: i64 = try stack.popI64();
        var num_zeroes = @ctz(v);
        try stack.pushI64(num_zeroes);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Popcnt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Popcnt", pc, code, stack);
        var v: i64 = try stack.popI64();
        var num_bits_set = @popCount(v);
        try stack.pushI64(num_bits_set);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Add", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result = v1 +% v2;
        try stack.pushI64(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Sub", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var result = v1 -% v2;
        try stack.pushI64(result);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Mul", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var value = v1 *% v2;
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Div_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Div_S", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var value = std.math.divTrunc(i64, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Div_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Div_U", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var value_unsigned = std.math.divFloor(u64, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else if (e == error.Overflow) {
                return error.TrapIntegerOverflow;
            } else {
                return e;
            }
        };
        var value = @bitCast(i64, value_unsigned);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rem_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Rem_S", pc, code, stack);
        var v2: i64 = try stack.popI64();
        var v1: i64 = try stack.popI64();
        var denom = try std.math.absInt(v2);
        var value = std.math.rem(i64, v1, denom) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rem_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Rem_U", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var value_unsigned = std.math.rem(u64, v1, v2) catch |e| {
            if (e == error.DivisionByZero) {
                return error.TrapIntegerDivisionByZero;
            } else {
                return e;
            }
        };
        var value = @bitCast(i64, value_unsigned);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_And(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_And", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var value = @bitCast(i64, v1 & v2);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Or(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Or", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var value = @bitCast(i64, v1 | v2);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Xor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Xor", pc, code, stack);
        var v2: u64 = @bitCast(u64, try stack.popI64());
        var v1: u64 = @bitCast(u64, try stack.popI64());
        var value = @bitCast(i64, v1 ^ v2);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Shl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Shl", pc, code, stack);
        var shift_unsafe: i64 = try stack.popI64();
        var int: i64 = try stack.popI64();
        var shift: i64 = try std.math.mod(i64, shift_unsafe, 64);
        var value = std.math.shl(i64, int, shift);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Shr_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Shr_S", pc, code, stack);
        var shift_unsafe: i64 = try stack.popI64();
        var int: i64 = try stack.popI64();
        var shift = try std.math.mod(i64, shift_unsafe, 64);
        var value = std.math.shr(i64, int, shift);
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Shr_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Shr_U", pc, code, stack);
        var shift_unsafe: u64 = @bitCast(u64, try stack.popI64());
        var int: u64 = @bitCast(u64, try stack.popI64());
        var shift = try std.math.mod(u64, shift_unsafe, 64);
        var value = @bitCast(i64, std.math.shr(u64, int, shift));
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rotl(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Rotl", pc, code, stack);
        var rot: u64 = @bitCast(u64, try stack.popI64());
        var int: u64 = @bitCast(u64, try stack.popI64());
        var value = @bitCast(i64, std.math.rotl(u64, int, rot));
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Rotr(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Rotr", pc, code, stack);
        var rot: u64 = @bitCast(u64, try stack.popI64());
        var int: u64 = @bitCast(u64, try stack.popI64());
        var value = @bitCast(i64, std.math.rotr(u64, int, rot));
        try stack.pushI64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Abs", pc, code, stack);
        var f = try stack.popF32();
        var value = std.math.fabs(f);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Neg", pc, code, stack);
        var f = try stack.popF32();
        try stack.pushF32(-f);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Ceil(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Ceil", pc, code, stack);
        var f = try stack.popF32();
        var value = @ceil(f);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Floor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Floor", pc, code, stack);
        var f = try stack.popF32();
        var value = @floor(f);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Trunc(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Trunc", pc, code, stack);
        var f = try stack.popF32();
        var value = std.math.trunc(f);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Nearest(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Nearest", pc, code, stack);
        var f = try stack.popF32();
        var value: f32 = undefined;
        var ceil = @ceil(f);
        var floor = @floor(f);
        if (ceil - f == f - floor) {
            value = if (@mod(ceil, 2) == 0) ceil else floor;
        } else {
            value = @round(f);
        }
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Sqrt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Sqrt", pc, code, stack);
        var f = try stack.popF32();
        var value = std.math.sqrt(f);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Add", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value = v1 + v2;
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Sub", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value = v1 - v2;
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Mul", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value = v1 * v2;
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Div", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value = v1 / v2;
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Min(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Min", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value = OpHelpers.propagateNanWithOp(std.math.min, v1, v2);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Max(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Max", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value = OpHelpers.propagateNanWithOp(std.math.max, v1, v2);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Copysign(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Copysign", pc, code, stack);
        var v2 = try stack.popF32();
        var v1 = try stack.popF32();
        var value = std.math.copysign(v1, v2);
        try stack.pushF32(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Abs(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Abs", pc, code, stack);
        var f = try stack.popF64();
        var value = std.math.fabs(f);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Neg(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Neg", pc, code, stack);
        var f = try stack.popF64();
        try stack.pushF64(-f);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Ceil(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Ceil", pc, code, stack);
        var f = try stack.popF64();
        var value = @ceil(f);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Floor(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Floor", pc, code, stack);
        var f = try stack.popF64();
        var value = @floor(f);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Trunc(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Trunc", pc, code, stack);
        var f = try stack.popF64();
        var value = @trunc(f);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Nearest(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Nearest", pc, code, stack);
        var f = try stack.popF64();
        var value: f64 = undefined;
        var ceil = @ceil(f);
        var floor = @floor(f);
        if (ceil - f == f - floor) {
            value = if (@mod(ceil, 2) == 0) ceil else floor;
        } else {
            value = @round(f);
        }
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Sqrt(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Sqrt", pc, code, stack);
        var f = try stack.popF64();
        var value = std.math.sqrt(f);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Add(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Add", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value = v1 + v2;
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Sub(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Sub", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value = v1 - v2;
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Mul(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Mul", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value = v1 * v2;
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Div(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Div", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value = v1 / v2;
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Min(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Min", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value = OpHelpers.propagateNanWithOp(std.math.min, v1, v2);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Max(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Max", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value = OpHelpers.propagateNanWithOp(std.math.max, v1, v2);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Copysign(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Copysign", pc, code, stack);
        var v2 = try stack.popF64();
        var v1 = try stack.popF64();
        var value = std.math.copysign(v1, v2);
        try stack.pushF64(value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Wrap_I64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Wrap_I64", pc, code, stack);
        var v = try stack.popI64();
        var mod = @truncate(i32, v);
        try stack.pushI32(mod);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_F32_S", pc, code, stack);
        var v = try stack.popF32();
        var int = try OpHelpers.truncateTo(i32, v);
        try stack.pushI32(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_F32_U", pc, code, stack);
        var v = try stack.popF32();
        var int = try OpHelpers.truncateTo(u32, v);
        try stack.pushI32(@bitCast(i32, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_F64_S", pc, code, stack);
        var v = try stack.popF64();
        var int = try OpHelpers.truncateTo(i32, v);
        try stack.pushI32(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_F64_U", pc, code, stack);
        var v = try stack.popF64();
        var int = try OpHelpers.truncateTo(u32, v);
        try stack.pushI32(@bitCast(i32, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend_I32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Extend_I32_S", pc, code, stack);
        var v32 = try stack.popI32();
        var v64: i64 = v32;
        try stack.pushI64(v64);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend_I32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Extend_I32_U", pc, code, stack);
        var v32 = try stack.popI32();
        var v64: u64 = @bitCast(u32, v32);
        try stack.pushI64(@bitCast(i64, v64));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_F32_S", pc, code, stack);
        var v = try stack.popF32();
        var int = try OpHelpers.truncateTo(i64, v);
        try stack.pushI64(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_F32_U", pc, code, stack);
        var v = try stack.popF32();
        var int = try OpHelpers.truncateTo(u64, v);
        try stack.pushI64(@bitCast(i64, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_F64_S", pc, code, stack);
        var v = try stack.popF64();
        var int = try OpHelpers.truncateTo(i64, v);
        try stack.pushI64(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_F64_U", pc, code, stack);
        var v = try stack.popF64();
        var int = try OpHelpers.truncateTo(u64, v);
        try stack.pushI64(@bitCast(i64, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Convert_I32_S", pc, code, stack);
        var v = try stack.popI32();
        try stack.pushF32(@intToFloat(f32, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Convert_I32_U", pc, code, stack);
        var v = @bitCast(u32, try stack.popI32());
        try stack.pushF32(@intToFloat(f32, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Convert_I64_S", pc, code, stack);
        var v = try stack.popI64();
        try stack.pushF32(@intToFloat(f32, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Convert_I64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Convert_I64_U", pc, code, stack);
        var v = @bitCast(u64, try stack.popI64());
        try stack.pushF32(@intToFloat(f32, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Demote_F64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Demote_F64", pc, code, stack);
        var v = try stack.popF64();
        try stack.pushF32(@floatCast(f32, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Convert_I32_S", pc, code, stack);
        var v = try stack.popI32();
        try stack.pushF64(@intToFloat(f64, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Convert_I32_U", pc, code, stack);
        var v = @bitCast(u32, try stack.popI32());
        try stack.pushF64(@intToFloat(f64, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Convert_I64_S", pc, code, stack);
        var v = try stack.popI64();
        try stack.pushF64(@intToFloat(f64, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Convert_I64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Convert_I64_U", pc, code, stack);
        var v = @bitCast(u64, try stack.popI64());
        try stack.pushF64(@intToFloat(f64, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Promote_F32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Promote_F32", pc, code, stack);
        var v = try stack.popF32();
        try stack.pushF64(@floatCast(f64, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Reinterpret_F32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Reinterpret_F32", pc, code, stack);
        var v = try stack.popF32();
        try stack.pushI32(@bitCast(i32, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Reinterpret_F64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Reinterpret_F64", pc, code, stack);
        var v = try stack.popF64();
        try stack.pushI64(@bitCast(i64, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F32_Reinterpret_I32(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F32_Reinterpret_I32", pc, code, stack);
        var v = try stack.popI32();
        try stack.pushF32(@bitCast(f32, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_F64_Reinterpret_I64(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("F64_Reinterpret_I64", pc, code, stack);
        var v = try stack.popI64();
        try stack.pushF64(@bitCast(f64, v));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Extend8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Extend8_S", pc, code, stack);
        var v = try stack.popI32();
        var v_truncated = @truncate(i8, v);
        var v_extended: i32 = v_truncated;
        try stack.pushI32(v_extended);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Extend16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Extend16_S", pc, code, stack);
        var v = try stack.popI32();
        var v_truncated = @truncate(i16, v);
        var v_extended: i32 = v_truncated;
        try stack.pushI32(v_extended);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend8_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Extend8_S", pc, code, stack);
        var v = try stack.popI64();
        var v_truncated = @truncate(i8, v);
        var v_extended: i64 = v_truncated;
        try stack.pushI64(v_extended);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend16_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Extend16_S", pc, code, stack);
        var v = try stack.popI64();
        var v_truncated = @truncate(i16, v);
        var v_extended: i64 = v_truncated;
        try stack.pushI64(v_extended);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Extend32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Extend32_S", pc, code, stack);
        var v = try stack.popI64();
        var v_truncated = @truncate(i32, v);
        var v_extended: i64 = v_truncated;
        try stack.pushI64(v_extended);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Ref_Null(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Ref_Null", pc, code, stack);
        var valtype = code[pc].immediate.ValType;
        var val = try Val.nullRef(valtype);
        try stack.pushValue(val);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Ref_Is_Null(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Ref_Is_Null", pc, code, stack);
        const val: Val = try stack.popValue();
        const boolean: i32 = if (val.isNull()) 1 else 0;
        try stack.pushI32(boolean);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Ref_Func(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Ref_Func", pc, code, stack);
        const func_index: u32 = code[pc].immediate.Index;
        const val = Val{ .FuncRef = .{ .index = func_index, .module_instance = stack.topFrame().module_instance } };
        try stack.pushValue(val);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_Sat_F32_S", pc, code, stack);
        var v = try stack.popF32();
        var int = OpHelpers.saturatedTruncateTo(i32, v);
        try stack.pushI32(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_Sat_F32_U", pc, code, stack);
        var v = try stack.popF32();
        var int = OpHelpers.saturatedTruncateTo(u32, v);
        try stack.pushI32(@bitCast(i32, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_Sat_F64_S", pc, code, stack);
        var v = try stack.popF64();
        var int = OpHelpers.saturatedTruncateTo(i32, v);
        try stack.pushI32(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I32_Trunc_Sat_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I32_Trunc_Sat_F64_U", pc, code, stack);
        var v = try stack.popF64();
        var int = OpHelpers.saturatedTruncateTo(u32, v);
        try stack.pushI32(@bitCast(i32, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F32_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_Sat_F32_S", pc, code, stack);
        var v = try stack.popF32();
        var int = OpHelpers.saturatedTruncateTo(i64, v);
        try stack.pushI64(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F32_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_Sat_F32_U", pc, code, stack);
        var v = try stack.popF32();
        var int = OpHelpers.saturatedTruncateTo(u64, v);
        try stack.pushI64(@bitCast(i64, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F64_S(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_Sat_F64_S", pc, code, stack);
        var v = try stack.popF64();
        var int = OpHelpers.saturatedTruncateTo(i64, v);
        try stack.pushI64(int);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_I64_Trunc_Sat_F64_U(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("I64_Trunc_Sat_F64_U", pc, code, stack);
        var v = try stack.popF64();
        var int = OpHelpers.saturatedTruncateTo(u64, v);
        try stack.pushI64(@bitCast(i64, int));
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Init(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Memory_Init", pc, code, stack);
        const data_index: u32 = code[pc].immediate.Index;
        const data: *const DataDefinition = &stack.topFrame().module_instance.module_def.datas.items[data_index];
        const memory: *MemoryInstance = &stack.topFrame().module_instance.store.memories.items[0];

        const length = try stack.popI32();
        const data_offset = try stack.popI32();
        const memory_offset = try stack.popI32();

        if (length < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }
        if (data.bytes.items.len < data_offset + length or data_offset < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }
        if (memory.mem.items.len < memory_offset + length or memory_offset < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const data_offset_u32 = @intCast(u32, data_offset);
        const memory_offset_u32 = @intCast(u32, memory_offset);
        const length_u32 = @intCast(u32, length);

        var source = data.bytes.items[data_offset_u32 .. data_offset_u32 + length_u32];
        var destination = memory.mem.items[memory_offset_u32 .. memory_offset_u32 + length_u32];
        std.mem.copy(u8, destination, source);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Data_Drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Data_Drop", pc, code, stack);
        const data_index: u32 = code[pc].immediate.Index;
        var data: *DataDefinition = &stack.topFrame().module_instance.module_def.datas.items[data_index];
        data.bytes.clearAndFree();
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Copy(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Memory_Copy", pc, code, stack);
        const memory: *MemoryInstance = &stack.topFrame().module_instance.store.memories.items[0];

        const length = try stack.popI32();
        const source_offset = try stack.popI32();
        const dest_offset = try stack.popI32();

        if (length < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }
        if (memory.mem.items.len < source_offset + length or source_offset < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }
        if (memory.mem.items.len < dest_offset + length or dest_offset < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const source_offset_u32 = @intCast(u32, source_offset);
        const dest_offset_u32 = @intCast(u32, dest_offset);
        const length_u32 = @intCast(u32, length);

        var source = memory.mem.items[source_offset_u32 .. source_offset_u32 + length_u32];
        var destination = memory.mem.items[dest_offset_u32 .. dest_offset_u32 + length_u32];

        if (@ptrToInt(destination.ptr) < @ptrToInt(source.ptr)) {
            std.mem.copy(u8, destination, source);
        } else {
            std.mem.copyBackwards(u8, destination, source);
        }
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Memory_Fill(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Memory_Fill", pc, code, stack);
        const memory: *MemoryInstance = &stack.topFrame().module_instance.store.memories.items[0];

        const length = try stack.popI32();
        const value: u8 = @truncate(u8, @bitCast(u32, try stack.popI32()));
        const offset = try stack.popI32();

        if (length < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }
        if (memory.mem.items.len < offset + length or offset < 0) {
            return error.TrapOutOfBoundsMemoryAccess;
        }

        const offset_u32 = @intCast(u32, offset);
        const length_u32 = @intCast(u32, length);

        var destination = memory.mem.items[offset_u32 .. offset_u32 + length_u32];

        std.mem.set(u8, destination, value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Init(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table_Init", pc, code, stack);
        const pair: TablePairImmediates = code[pc].immediate.TablePair;
        const elem_index = pair.index_x;
        const table_index = pair.index_y;

        const elem: *const ElementInstance = &stack.topFrame().module_instance.store.elements.items[elem_index];
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);

        const length_i32 = try stack.popI32();
        const elem_start_index = try stack.popI32();
        const table_start_index = try stack.popI32();

        if (elem_start_index + length_i32 > elem.refs.items.len or elem_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (table_start_index + length_i32 > table.refs.items.len or table_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (length_i32 < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }

        const elem_begin = @intCast(usize, elem_start_index);
        const table_begin = @intCast(usize, table_start_index);
        const length = @intCast(usize, length_i32);

        var dest: []Val = table.refs.items[table_begin .. table_begin + length];
        var src: []const Val = elem.refs.items[elem_begin .. elem_begin + length];
        std.mem.copy(Val, dest, src);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Elem_Drop(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Elem_Drop", pc, code, stack);
        const elem_index: u32 = code[pc].immediate.Index;
        var elem: *ElementInstance = &stack.topFrame().module_instance.store.elements.items[elem_index];
        elem.refs.clearAndFree();
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Copy(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table_Copy", pc, code, stack);
        const pair: TablePairImmediates = code[pc].immediate.TablePair;
        const dest_table_index = pair.index_x;
        const src_table_index = pair.index_y;

        const dest_table: *TableInstance = stack.topFrame().module_instance.store.getTable(dest_table_index);
        const src_table: *const TableInstance = stack.topFrame().module_instance.store.getTable(src_table_index);

        const length_i32 = try stack.popI32();
        const src_start_index = try stack.popI32();
        const dest_start_index = try stack.popI32();

        if (src_start_index + length_i32 > src_table.refs.items.len or src_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (dest_start_index + length_i32 > dest_table.refs.items.len or dest_start_index < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }
        if (length_i32 < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }

        const dest_begin = @intCast(usize, dest_start_index);
        const src_begin = @intCast(usize, src_start_index);
        const length = @intCast(usize, length_i32);

        var dest: []Val = dest_table.refs.items[dest_begin .. dest_begin + length];
        var src: []const Val = src_table.refs.items[src_begin .. src_begin + length];
        if (dest_start_index <= src_start_index) {
            std.mem.copy(Val, dest, src);
        } else {
            std.mem.copyBackwards(Val, dest, src);
        }
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Grow(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table_Grow", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const length = @bitCast(u32, try stack.popI32());
        const init_value = try stack.popValue();
        const old_length = @intCast(i32, table.refs.items.len);
        const return_value: i32 = if (table.grow(length, init_value)) old_length else -1;
        try stack.pushI32(return_value);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Size(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table_Size", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);
        const length = @intCast(i32, table.refs.items.len);
        try stack.pushI32(length);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }

    fn op_Table_Fill(pc: u32, code: [*]const Instruction, stack: *Stack) anyerror!void {
        debugPreamble("Table_Fill", pc, code, stack);
        const table_index: u32 = code[pc].immediate.Index;
        const table: *TableInstance = stack.topFrame().module_instance.store.getTable(table_index);

        const length_i32 = try stack.popI32();
        const funcref = try stack.popValue();
        const dest_table_index = try stack.popI32();

        if (dest_table_index + length_i32 > table.refs.items.len or length_i32 < 0) {
            return error.TrapOutOfBoundsTableAccess;
        }

        const dest_begin = @intCast(usize, dest_table_index);
        const length = @intCast(usize, length_i32);

        var dest: []Val = table.refs.items[dest_begin .. dest_begin + length];

        std.mem.set(Val, dest, funcref);
        try @call(.{ .modifier = .always_tail }, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, stack });
    }
};

pub const ModuleDefinition = struct {
    const Code = struct {
        instructions: std.ArrayList(Instruction),

        // Instruction.immediate indexes these arrays depending on the opcode
        branch_table: std.ArrayList(BranchTableImmediates),
    };

    const Imports = struct {
        functions: std.ArrayList(FunctionImportDefinition),
        tables: std.ArrayList(TableImportDefinition),
        memories: std.ArrayList(MemoryImportDefinition),
        globals: std.ArrayList(GlobalImportDefinition),
    };

    const Exports = struct {
        functions: std.ArrayList(ExportDefinition),
        tables: std.ArrayList(ExportDefinition),
        memories: std.ArrayList(ExportDefinition),
        globals: std.ArrayList(ExportDefinition),
    };

    allocator: std.mem.Allocator,

    code: Code,

    types: std.ArrayList(FunctionTypeDefinition),
    imports: Imports,
    functions: std.ArrayList(FunctionDefinition),
    globals: std.ArrayList(GlobalDefinition),
    tables: std.ArrayList(TableDefinition),
    memories: std.ArrayList(MemoryDefinition),
    elements: std.ArrayList(ElementDefinition),
    exports: Exports,
    datas: std.ArrayList(DataDefinition),
    custom_sections: std.ArrayList(CustomSection),

    start_func_index: ?u32 = null,
    data_count: ?u32 = null,

    if_to_else_offsets: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList

    is_decoded: bool = false,

    pub fn init(allocator: std.mem.Allocator) ModuleDefinition {
        var module = ModuleDefinition{
            .allocator = allocator,
            .code = Code{
                .instructions = std.ArrayList(Instruction).init(allocator),
                .branch_table = std.ArrayList(BranchTableImmediates).init(allocator),
            },
            .types = std.ArrayList(FunctionTypeDefinition).init(allocator),
            .imports = Imports{
                .functions = std.ArrayList(FunctionImportDefinition).init(allocator),
                .tables = std.ArrayList(TableImportDefinition).init(allocator),
                .memories = std.ArrayList(MemoryImportDefinition).init(allocator),
                .globals = std.ArrayList(GlobalImportDefinition).init(allocator),
            },
            .functions = std.ArrayList(FunctionDefinition).init(allocator),
            .globals = std.ArrayList(GlobalDefinition).init(allocator),
            .tables = std.ArrayList(TableDefinition).init(allocator),
            .memories = std.ArrayList(MemoryDefinition).init(allocator),
            .elements = std.ArrayList(ElementDefinition).init(allocator),
            .exports = Exports{
                .functions = std.ArrayList(ExportDefinition).init(allocator),
                .tables = std.ArrayList(ExportDefinition).init(allocator),
                .memories = std.ArrayList(ExportDefinition).init(allocator),
                .globals = std.ArrayList(ExportDefinition).init(allocator),
            },
            .datas = std.ArrayList(DataDefinition).init(allocator),
            .custom_sections = std.ArrayList(CustomSection).init(allocator),

            .if_to_else_offsets = std.AutoHashMap(u32, u32).init(allocator),
        };

        return module;
    }

    pub fn decode(self: *ModuleDefinition, wasm: []const u8) anyerror!void {
        if (self.is_decoded == false) {
            self.is_decoded = true;
        } else {
            return AssertError.ModuleAlreadyDecoded;
        }

        self.decode_internal(wasm) catch |e| {
            var wrapped_error: anyerror = switch (e) {
                error.EndOfStream => error.MalformedUnexpectedEnd,
                else => e,
            };
            return wrapped_error;
        };
    }

    fn decode_internal(self: *ModuleDefinition, wasm: []const u8) anyerror!void {
        const DecodeHelpers = struct {
            fn readRefValue(valtype: ValType, reader: anytype) !Val {
                switch (valtype) {
                    .FuncRef => {
                        const func_index = try decodeLEB128(u32, reader);
                        return Val.funcrefFromIndex(func_index);
                    },
                    .ExternRef => {
                        unreachable; // TODO
                    },
                    else => unreachable,
                }
            }

            fn readName(reader: anytype, _allocator: std.mem.Allocator) ![]const u8 {
                const name_length = try decodeLEB128(u32, reader);

                var name: []u8 = try _allocator.alloc(u8, name_length);
                errdefer _allocator.free(name);
                var read_length = try reader.read(name);
                if (read_length != name_length) {
                    return error.MalformedUnexpectedEnd;
                }

                if (std.unicode.utf8ValidateSlice(name) == false) {
                    return error.MalformedUTF8Encoding;
                }

                return name;
            }
        };

        var allocator = self.allocator;
        var validator = ModuleValidator.init(allocator);
        defer validator.deinit();

        var stream = std.io.fixedBufferStream(wasm);
        var reader = stream.reader();

        // wasm header
        {
            const magic = try reader.readIntBig(u32);
            if (magic != 0x0061736D) {
                return error.MalformedMagicSignature;
            }
            const version = try reader.readIntLittle(u32);
            if (version != 1) {
                return error.MalformedUnsupportedWasmVersion;
            }
        }

        var num_functions_parsed: u32 = 0;

        while (stream.pos < stream.buffer.len) {
            const section_id: Section = std.meta.intToEnum(Section, try reader.readByte()) catch {
                return error.MalformedSectionId;
            };
            const section_size_bytes: usize = try decodeLEB128(u32, reader);
            const section_start_pos = stream.pos;

            switch (section_id) {
                .Custom => {
                    if (section_size_bytes == 0) {
                        return error.MalformedUnexpectedEnd;
                    }

                    var name = try DecodeHelpers.readName(reader, allocator);
                    errdefer allocator.free(name);

                    var section = CustomSection{
                        .name = name,
                        .data = std.ArrayList(u8).init(allocator),
                    };

                    const name_length: usize = stream.pos - section_start_pos;
                    const data_length: usize = section_size_bytes - name_length;
                    try section.data.resize(data_length);
                    const data_length_read = try reader.read(section.data.items);
                    if (data_length != data_length_read) {
                        return error.MalformedUnexpectedEnd;
                    }

                    try self.custom_sections.append(section);
                },
                .FunctionType => {
                    const num_types = try decodeLEB128(u32, reader);

                    try self.types.ensureTotalCapacity(num_types);

                    var types_index: u32 = 0;
                    while (types_index < num_types) : (types_index += 1) {
                        const sentinel = try reader.readByte();
                        if (sentinel != k_function_type_sentinel_byte) {
                            return error.MalformedTypeSentinel;
                        }

                        const num_params = try decodeLEB128(u32, reader);

                        var func = FunctionTypeDefinition{ .num_params = num_params, .types = std.ArrayList(ValType).init(allocator) };
                        errdefer func.types.deinit();

                        var params_left = num_params;
                        while (params_left > 0) {
                            params_left -= 1;

                            var param_type = try ValType.decode(reader);
                            try func.types.append(param_type);
                        }

                        const num_returns = try decodeLEB128(u32, reader);
                        var returns_left = num_returns;
                        while (returns_left > 0) {
                            returns_left -= 1;

                            var return_type = try ValType.decode(reader);
                            try func.types.append(return_type);
                        }

                        try self.types.append(func);
                    }
                },
                .Import => {
                    const num_imports = try decodeLEB128(u32, reader);

                    var import_index: u32 = 0;
                    while (import_index < num_imports) : (import_index += 1) {
                        var module_name: []const u8 = try DecodeHelpers.readName(reader, allocator);
                        errdefer allocator.free(module_name);

                        var import_name: []const u8 = try DecodeHelpers.readName(reader, allocator);
                        errdefer allocator.free(import_name);

                        const names = ImportNames{
                            .module_name = module_name,
                            .import_name = import_name,
                        };

                        const desc = try reader.readByte();
                        switch (desc) {
                            0x00 => {
                                const type_index = try decodeLEB128(u32, reader);
                                try ModuleValidator.validateTypeIndex(type_index, self);
                                try self.imports.functions.append(FunctionImportDefinition{
                                    .names = names,
                                    .type_index = type_index,
                                });
                            },
                            0x01 => {
                                const valtype = try ValType.decode(reader);
                                if (valtype.isRefType() == false) {
                                    return error.MalformedInvalidImport;
                                }
                                const limits = try Limits.decode(reader);
                                try self.imports.tables.append(TableImportDefinition{
                                    .names = names,
                                    .reftype = valtype,
                                    .limits = limits,
                                });
                            },
                            0x02 => {
                                const limits = try Limits.decode(reader);
                                try self.imports.memories.append(MemoryImportDefinition{
                                    .names = names,
                                    .limits = limits,
                                });
                            },
                            0x03 => {
                                const valtype = try ValType.decode(reader);
                                const mut = try GlobalMut.decode(reader);

                                try self.imports.globals.append(GlobalImportDefinition{
                                    .names = names,
                                    .valtype = valtype,
                                    .mut = mut,
                                });
                            },
                            else => return error.MalformedInvalidImport,
                        }
                    }
                },
                .Function => {
                    const num_funcs = try decodeLEB128(u32, reader);

                    try self.functions.ensureTotalCapacity(num_funcs);

                    var func_index: u32 = 0;
                    while (func_index < num_funcs) : (func_index += 1) {
                        var func = FunctionDefinition{
                            .type_index = try decodeLEB128(u32, reader),
                            .locals = std.ArrayList(ValType).init(allocator),

                            // we'll fix these up later when we find them in the Code section
                            .offset_into_instructions = 0,
                            .size = 0,
                            .continuation = 0,
                        };

                        self.functions.addOneAssumeCapacity().* = func;
                    }
                },
                .Table => {
                    const num_tables = try decodeLEB128(u32, reader);

                    try self.tables.ensureTotalCapacity(num_tables);

                    var table_index: u32 = 0;
                    while (table_index < num_tables) : (table_index += 1) {
                        const valtype = try ValType.decode(reader);
                        if (valtype.isRefType() == false) {
                            return error.InvalidTableType;
                        }

                        const limits = try Limits.decode(reader);

                        try self.tables.append(TableDefinition{
                            .reftype = valtype,
                            .limits = limits,
                        });
                    }
                },
                .Memory => {
                    const num_memories = try decodeLEB128(u32, reader);

                    if (num_memories > 1) {
                        return error.ValidationMultipleMemories;
                    }

                    try self.memories.ensureTotalCapacity(num_memories);

                    var memory_index: u32 = 0;
                    while (memory_index < num_memories) : (memory_index += 1) {
                        var limits = try Limits.decode(reader);

                        if (limits.min > MemoryInstance.k_max_pages) {
                            return error.ValidationMemoryMaxPagesExceeded;
                        }

                        if (limits.max) |max| {
                            if (max < limits.min) {
                                return error.ValidationMemoryInvalidMaxLimit;
                            }
                            if (max > MemoryInstance.k_max_pages) {
                                return error.ValidationMemoryMaxPagesExceeded;
                            }
                        }

                        var def = MemoryDefinition{
                            .limits = limits,
                        };
                        try self.memories.append(def);
                    }
                },
                .Global => {
                    const num_globals = try decodeLEB128(u32, reader);

                    try self.globals.ensureTotalCapacity(num_globals);

                    var global_index: u32 = 0;
                    while (global_index < num_globals) : (global_index += 1) {
                        var valtype = try ValType.decode(reader);
                        var mut = try GlobalMut.decode(reader);

                        const expr = try ConstantExpression.decode(reader, self, .Immutable, valtype);

                        if (std.meta.activeTag(expr) == .Value) {
                            if (std.meta.activeTag(expr.Value) == .FuncRef) {
                                if (expr.Value.isNull() == false) {
                                    const index: u32 = expr.Value.FuncRef.index;
                                    try ModuleValidator.validateFunctionIndex(index, self);
                                }
                            }
                        }

                        try self.globals.append(GlobalDefinition{
                            .valtype = valtype,
                            .expr = expr,
                            .mut = mut,
                        });
                    }
                },
                .Export => {
                    const num_exports = try decodeLEB128(u32, reader);

                    var export_names = std.StringHashMap(void).init(allocator);
                    defer export_names.deinit();

                    var export_index: u32 = 0;
                    while (export_index < num_exports) : (export_index += 1) {
                        var name: []const u8 = try DecodeHelpers.readName(reader, allocator);
                        errdefer allocator.free(name);

                        {
                            var getOrPutResult = try export_names.getOrPut(name);
                            if (getOrPutResult.found_existing == true) {
                                return error.ValidationDuplicateExportName;
                            }
                        }

                        const exportType = @intToEnum(ExportType, try reader.readByte());
                        const item_index = try decodeLEB128(u32, reader);
                        const def = ExportDefinition{ .name = name, .index = item_index };

                        switch (exportType) {
                            .Function => {
                                try ModuleValidator.validateFunctionIndex(item_index, self);
                                try self.exports.functions.append(def);
                            },
                            .Table => {
                                try ModuleValidator.validateTableIndex(item_index, self);
                                try self.exports.tables.append(def);
                            },
                            .Memory => {
                                if (self.imports.memories.items.len + self.memories.items.len <= item_index) {
                                    return error.ValidationUnknownMemory;
                                }
                                try self.exports.memories.append(def);
                            },
                            .Global => {
                                try ModuleValidator.validateGlobalIndex(item_index, self);
                                try self.exports.globals.append(def);
                            },
                        }
                    }
                },
                .Start => {
                    if (self.start_func_index != null) {
                        return error.MalformedMultipleStartSections;
                    }

                    self.start_func_index = try decodeLEB128(u32, reader);

                    if (self.imports.functions.items.len + self.functions.items.len <= self.start_func_index.?) {
                        return error.ValidationUnknownFunction;
                    }

                    var func_type_index: usize = undefined;
                    if (self.start_func_index.? < self.imports.functions.items.len) {
                        func_type_index = self.imports.functions.items[self.start_func_index.?].type_index;
                    } else {
                        var local_func_index = self.start_func_index.? - self.imports.functions.items.len;
                        func_type_index = self.functions.items[local_func_index].type_index;
                    }

                    const func_type: *const FunctionTypeDefinition = &self.types.items[func_type_index];
                    if (func_type.types.items.len > 0) {
                        return error.ValidationStartFunctionType;
                    }
                },
                .Element => {
                    const ElementHelpers = struct {
                        fn readOffsetExpr(_reader: anytype, _module: *const ModuleDefinition) !ConstantExpression {
                            var expr = try ConstantExpression.decode(_reader, _module, .Immutable, .I32);
                            return expr;
                        }

                        fn readElemsVal(elems: *std.ArrayList(Val), valtype: ValType, _reader: anytype, _module: *const ModuleDefinition) !void {
                            const num_elems = try decodeLEB128(u32, _reader);
                            try elems.ensureTotalCapacity(num_elems);

                            var elem_index: u32 = 0;
                            while (elem_index < num_elems) : (elem_index += 1) {
                                const ref: Val = try DecodeHelpers.readRefValue(valtype, _reader);
                                if (valtype == .FuncRef) {
                                    try ModuleValidator.validateFunctionIndex(ref.FuncRef.index, _module);
                                }
                                try elems.append(ref);
                            }
                        }

                        fn readElemsExpr(elems: *std.ArrayList(ConstantExpression), _reader: anytype, _module: *const ModuleDefinition, expected_reftype: ValType) !void {
                            const num_elems = try decodeLEB128(u32, _reader);
                            try elems.ensureTotalCapacity(num_elems);

                            var elem_index: u32 = 0;
                            while (elem_index < num_elems) : (elem_index += 1) {
                                var expr = try ConstantExpression.decode(_reader, _module, .Any, expected_reftype);
                                try elems.append(expr);
                            }
                        }

                        fn readNullElemkind(_reader: anytype) !void {
                            var null_elemkind = try _reader.readByte();
                            if (null_elemkind != 0x00) {
                                return error.AssertInvalidBytecode;
                            }
                        }
                    };

                    const num_segments = try decodeLEB128(u32, reader);

                    try self.elements.ensureTotalCapacity(num_segments);

                    var segment_index: u32 = 0;
                    while (segment_index < num_segments) : (segment_index += 1) {
                        var flags = try decodeLEB128(u32, reader);

                        var def = ElementDefinition{
                            .mode = ElementMode.Active,
                            .reftype = ValType.FuncRef,
                            .table_index = 0,
                            .offset = null,
                            .elems_value = std.ArrayList(Val).init(allocator),
                            .elems_expr = std.ArrayList(ConstantExpression).init(allocator),
                        };
                        errdefer def.elems_value.deinit();
                        errdefer def.elems_expr.deinit();

                        switch (flags) {
                            0x00 => {
                                def.offset = try ElementHelpers.readOffsetExpr(reader, self);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader, self);
                            },
                            0x01 => {
                                def.mode = .Passive;
                                try ElementHelpers.readNullElemkind(reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader, self);
                            },
                            0x02 => {
                                def.table_index = try decodeLEB128(u32, reader);
                                def.offset = try ElementHelpers.readOffsetExpr(reader, self);
                                try ElementHelpers.readNullElemkind(reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader, self);
                            },
                            0x03 => {
                                def.mode = .Declarative;
                                try ElementHelpers.readNullElemkind(reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader, self);
                            },
                            0x04 => {
                                def.offset = try ElementHelpers.readOffsetExpr(reader, self);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader, self, def.reftype);
                            },
                            0x05 => {
                                def.mode = .Passive;
                                def.reftype = try ValType.decodeReftype(reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader, self, def.reftype);
                            },
                            0x06 => {
                                def.table_index = try decodeLEB128(u32, reader);
                                def.offset = try ElementHelpers.readOffsetExpr(reader, self);
                                def.reftype = try ValType.decodeReftype(reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader, self, def.reftype);
                            },
                            0x07 => {
                                def.mode = .Declarative;
                                def.reftype = try ValType.decodeReftype(reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader, self, def.reftype);
                            },
                            else => {
                                return error.MalformedElementType;
                            },
                        }

                        try self.elements.append(def);
                    }
                },
                .Code => {
                    const BlockData = struct {
                        begin_index: u32,
                        opcode: Opcode,
                    };
                    var block_stack = std.ArrayList(BlockData).init(allocator);
                    defer block_stack.deinit();

                    var instructions = &self.code.instructions;

                    const num_codes = try decodeLEB128(u32, reader);

                    if (num_codes != self.functions.items.len) {
                        return error.MalformedFunctionCodeSectionMismatch;
                    }

                    var code_index: u32 = 0;
                    while (code_index < num_codes) {
                        const code_size = try decodeLEB128(u32, reader);
                        const code_begin_pos = stream.pos;

                        var def: *FunctionDefinition = &self.functions.items[code_index];
                        def.offset_into_instructions = @intCast(u32, code_begin_pos);
                        def.size = code_size;

                        // parse locals
                        {
                            const num_locals = try decodeLEB128(u32, reader);

                            const TypeCount = struct {
                                valtype: ValType,
                                count: u32,
                            };
                            var local_types = std.ArrayList(TypeCount).init(allocator);
                            defer local_types.deinit();
                            try local_types.ensureTotalCapacity(num_locals);

                            var locals_total: usize = 0;
                            var locals_index: u32 = 0;
                            try def.locals.ensureTotalCapacity(num_locals);
                            while (locals_index < num_locals) : (locals_index += 1) {
                                const n = try decodeLEB128(u32, reader);
                                const local_type = try ValType.decode(reader);

                                locals_total += n;
                                if (locals_total >= std.math.maxInt(u32)) {
                                    return error.MalformedTooManyLocals;
                                }
                                local_types.appendAssumeCapacity(TypeCount{ .valtype = local_type, .count = n });
                            }

                            try def.locals.ensureTotalCapacity(locals_total);

                            for (local_types.items) |type_count| {
                                def.locals.appendNTimesAssumeCapacity(type_count.valtype, type_count.count);
                            }
                        }

                        const instruction_begin_offset = @intCast(u32, instructions.items.len);
                        self.functions.items[code_index].offset_into_instructions = instruction_begin_offset;
                        try block_stack.append(BlockData{
                            .begin_index = instruction_begin_offset,
                            .opcode = .Block,
                        });

                        try validator.beginValidateCode(self, &self.functions.items[code_index]);

                        var parsing_code = true;
                        while (parsing_code) {
                            const instruction_index = @intCast(u32, instructions.items.len);

                            var instruction: Instruction = try Instruction.decode(reader, self);

                            if (instruction.opcode.beginsBlock()) {
                                try block_stack.append(BlockData{
                                    .begin_index = instruction_index,
                                    .opcode = instruction.opcode,
                                });
                            } else if (instruction.opcode == .Else) {
                                const block: *const BlockData = &block_stack.items[block_stack.items.len - 1];
                                try self.if_to_else_offsets.putNoClobber(block.begin_index, instruction_index);
                                // the else gets the matching if's immediates
                                instruction.immediate = instructions.items[block.begin_index].immediate;
                            } else if (instruction.opcode == .End) {
                                const block: BlockData = block_stack.orderedRemove(block_stack.items.len - 1);
                                if (block_stack.items.len == 0) {
                                    parsing_code = false;

                                    def.continuation = instruction_index;

                                    block_stack.clearRetainingCapacity();

                                    num_functions_parsed += 1;
                                } else {
                                    var block_instruction: *Instruction = &instructions.items[block.begin_index];

                                    // fixup the block continuations in previously-emitted Instructions
                                    if (block.opcode == .Loop) {
                                        block_instruction.immediate.Block.continuation = block.begin_index;
                                    } else {
                                        block_instruction.immediate.Block.continuation = instruction_index;

                                        var else_index_or_null = self.if_to_else_offsets.get(block.begin_index);
                                        if (else_index_or_null) |index| {
                                            var else_instruction: *Instruction = &instructions.items[index];
                                            else_instruction.immediate = block_instruction.immediate;
                                        }
                                    }
                                }
                            }

                            try validator.validateCode(self, &self.functions.items[code_index], instruction);

                            switch (instruction.opcode) {
                                .Noop => {}, // no need to emit noops since they don't do anything
                                else => {
                                    try instructions.append(instruction);
                                },
                            }
                        }

                        try validator.endValidateCode();

                        const code_actual_size = stream.pos - code_begin_pos;
                        if (code_actual_size != code_size) {
                            return error.MalformedSectionSizeMismatch;
                        }

                        code_index += 1;
                    }

                    // TODO assemble all instructions into a stream

                },
                .Data => {
                    const num_datas = try decodeLEB128(u32, reader);

                    if (self.data_count != null and num_datas != self.data_count.?) {
                        return error.MalformedDataCountMismatch;
                    }

                    var data_index: u32 = 0;
                    while (data_index < num_datas) : (data_index += 1) {
                        var data = try DataDefinition.decode(reader, self, allocator);
                        try self.datas.append(data);
                    }
                },
                .DataCount => {
                    self.data_count = try decodeLEB128(u32, reader);
                    try self.datas.ensureTotalCapacity(self.data_count.?);
                },
            }

            var consumed_bytes = stream.pos - section_start_pos;
            if (section_size_bytes != consumed_bytes) {
                return error.MalformedSectionSizeMismatch;
            }
        }

        for (self.elements.items) |elem_def| {
            if (elem_def.mode == .Active) {
                const valtype = try ModuleValidator.getTableReftype(self, elem_def.table_index);
                if (elem_def.reftype != valtype) {
                    return error.ValidationTypeMismatch;
                }
            }
        }

        if (self.imports.memories.items.len + self.memories.items.len > 1) {
            return error.ValidationMultipleMemories;
        }

        if (num_functions_parsed != self.functions.items.len) {
            return error.MalformedFunctionCodeSectionMismatch;
        }
    }

    pub fn deinit(self: *ModuleDefinition) void {
        self.code.instructions.deinit();
        for (self.code.branch_table.items) |*item| {
            item.label_ids.deinit();
        }
        self.code.branch_table.deinit();

        for (self.imports.functions.items) |*item| {
            self.allocator.free(item.names.module_name);
            self.allocator.free(item.names.import_name);
        }
        for (self.imports.tables.items) |*item| {
            self.allocator.free(item.names.module_name);
            self.allocator.free(item.names.import_name);
        }
        for (self.imports.memories.items) |*item| {
            self.allocator.free(item.names.module_name);
            self.allocator.free(item.names.import_name);
        }
        for (self.imports.globals.items) |*item| {
            self.allocator.free(item.names.module_name);
            self.allocator.free(item.names.import_name);
        }

        for (self.exports.functions.items) |*item| {
            self.allocator.free(item.name);
        }
        for (self.exports.tables.items) |*item| {
            self.allocator.free(item.name);
        }
        for (self.exports.memories.items) |*item| {
            self.allocator.free(item.name);
        }
        for (self.exports.globals.items) |*item| {
            self.allocator.free(item.name);
        }

        self.types.deinit();
        self.imports.functions.deinit();
        self.imports.tables.deinit();
        self.imports.memories.deinit();
        self.imports.globals.deinit();
        self.functions.deinit();
        self.globals.deinit();
        self.tables.deinit();
        self.memories.deinit();
        self.elements.deinit();
        self.exports.functions.deinit();
        self.exports.tables.deinit();
        self.exports.memories.deinit();
        self.exports.globals.deinit();
        self.datas.deinit();

        for (self.custom_sections.items) |*item| {
            self.allocator.free(item.name);
            item.data.deinit();
        }
        self.custom_sections.deinit();

        self.if_to_else_offsets.deinit();
    }
};

const ImportType = enum(u8) {
    Host,
    Wasm,
};

const HostFunctionCallback = *const fn (userdata: ?*anyopaque, params: []const Val, returns: []Val) void;

const HostFunction = struct {
    userdata: ?*anyopaque,
    func_def: FunctionTypeDefinition,
    callback: HostFunctionCallback,
};

const ImportDataWasm = struct {
    module_instance: *ModuleInstance,
    index: u32,
};

pub const FunctionImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: HostFunction,
        Wasm: ImportDataWasm,
    },

    fn dupe(import: *const FunctionImport, allocator: std.mem.Allocator) !FunctionImport {
        var copy = import.*;
        copy.name = try allocator.dupe(u8, copy.name);
        switch (copy.data) {
            .Host => |*data| {
                var func_def = FunctionTypeDefinition{
                    .types = std.ArrayList(ValType).init(allocator),
                    .num_params = data.func_def.num_params,
                };
                try func_def.types.appendSlice(data.func_def.types.items);
                data.func_def = func_def;
            },
            .Wasm => {},
        }

        return copy;
    }

    fn isTypeSignatureEql(import: *const FunctionImport, type_signature: *const FunctionTypeDefinition) bool {
        var type_comparer = FunctionTypeContext{};
        switch (import.data) {
            .Host => |data| {
                return type_comparer.eql(&data.func_def, type_signature);
            },
            .Wasm => |data| {
                var func_type_def: *const FunctionTypeDefinition = data.module_instance.findFuncTypeDef(data.index);
                return type_comparer.eql(func_type_def, type_signature);
            },
        }
    }
};

pub const TableImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: *TableInstance,
        Wasm: ImportDataWasm,
    },

    fn dupe(import: *const TableImport, allocator: std.mem.Allocator) !TableImport {
        var copy = import.*;
        copy.name = try allocator.dupe(u8, copy.name);
        return copy;
    }
};

pub const MemoryImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: *MemoryInstance,
        Wasm: ImportDataWasm,
    },

    fn dupe(import: *const MemoryImport, allocator: std.mem.Allocator) !MemoryImport {
        var copy = import.*;
        copy.name = try allocator.dupe(u8, copy.name);
        return copy;
    }
};

pub const GlobalImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: *GlobalInstance,
        Wasm: ImportDataWasm,
    },

    fn dupe(import: *const GlobalImport, allocator: std.mem.Allocator) !GlobalImport {
        var copy = import.*;
        copy.name = try allocator.dupe(u8, copy.name);
        return copy;
    }
};

pub const ModuleImports = struct {
    name: []const u8,
    instance: ?*ModuleInstance,
    functions: std.ArrayList(FunctionImport),
    tables: std.ArrayList(TableImport),
    memories: std.ArrayList(MemoryImport),
    globals: std.ArrayList(GlobalImport),
    allocator: std.mem.Allocator,

    pub fn init(name: []const u8, instance: ?*ModuleInstance, allocator: std.mem.Allocator) !ModuleImports {
        return ModuleImports{
            .name = try allocator.dupe(u8, name),
            .instance = instance,
            .functions = std.ArrayList(FunctionImport).init(allocator),
            .tables = std.ArrayList(TableImport).init(allocator),
            .memories = std.ArrayList(MemoryImport).init(allocator),
            .globals = std.ArrayList(GlobalImport).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn addHostFunction(self: *ModuleImports, name: []const u8, userdata: ?*anyopaque, param_types: []const ValType, return_types: []const ValType, callback: HostFunctionCallback) !void {
        std.debug.assert(self.instance == null); // cannot add host functions to an imports that is intended to be bound to a module instance

        var type_list = std.ArrayList(ValType).init(self.allocator);
        try type_list.appendSlice(param_types);
        try type_list.appendSlice(return_types);

        try self.functions.append(FunctionImport{
            .name = try self.allocator.dupe(u8, name),
            .data = .{
                .Host = HostFunction{
                    .userdata = userdata,
                    .func_def = FunctionTypeDefinition{
                        .types = type_list,
                        .num_params = @intCast(u32, param_types.len),
                    },
                    .callback = callback,
                },
            },
        });
    }

    pub fn deinit(self: *ModuleImports) void {
        self.allocator.free(self.name);

        for (self.functions.items) |*item| {
            self.allocator.free(item.name);
            switch (item.data) {
                .Host => |h| h.func_def.types.deinit(),
                else => {},
            }
        }
        self.functions.deinit();

        for (self.tables.items) |*item| {
            self.allocator.free(item.name);
        }
        self.tables.deinit();

        for (self.memories.items) |*item| {
            self.allocator.free(item.name);
        }
        self.memories.deinit();

        for (self.globals.items) |*item| {
            self.allocator.free(item.name);
        }
        self.globals.deinit();
    }
};

pub const Store = struct {
    functions: std.ArrayList(FunctionInstance),
    tables: std.ArrayList(TableInstance),
    memories: std.ArrayList(MemoryInstance),
    globals: std.ArrayList(GlobalInstance),
    elements: std.ArrayList(ElementInstance),
    imports: struct {
        functions: std.ArrayList(FunctionImport),
        tables: std.ArrayList(TableImport),
        memories: std.ArrayList(MemoryImport),
        globals: std.ArrayList(GlobalImport),
    },

    fn init(allocator: std.mem.Allocator) Store {
        var store = Store{
            .imports = .{
                .functions = std.ArrayList(FunctionImport).init(allocator),
                .tables = std.ArrayList(TableImport).init(allocator),
                .memories = std.ArrayList(MemoryImport).init(allocator),
                .globals = std.ArrayList(GlobalImport).init(allocator),
            },
            .functions = std.ArrayList(FunctionInstance).init(allocator),
            .tables = std.ArrayList(TableInstance).init(allocator),
            .memories = std.ArrayList(MemoryInstance).init(allocator),
            .globals = std.ArrayList(GlobalInstance).init(allocator),
            .elements = std.ArrayList(ElementInstance).init(allocator),
        };

        return store;
    }

    fn deinit(self: *Store) void {
        self.functions.deinit();

        for (self.tables.items) |*item| {
            item.deinit();
        }
        self.tables.deinit();

        for (self.memories.items) |*item| {
            item.deinit();
        }
        self.memories.deinit();

        self.globals.deinit();
        self.elements.deinit();
    }

    fn getTable(self: *Store, index: usize) *TableInstance {
        if (self.imports.tables.items.len <= index) {
            var instance_index = index - self.imports.tables.items.len;
            return &self.tables.items[instance_index];
        } else {
            var import: *TableImport = &self.imports.tables.items[index];
            return switch (import.data) {
                .Host => |data| data,
                .Wasm => |data| data.module_instance.store.getTable(data.index),
            };
        }
    }

    fn getMemory(self: *Store, index: usize) *MemoryInstance {
        if (self.imports.memories.items.len <= index) {
            var instance_index = index - self.imports.memories.items.len;
            return &self.memories.items[instance_index];
        } else {
            var import: *MemoryImport = &self.imports.memories.items[index];
            return switch (import.data) {
                .Host => |data| data,
                .Wasm => |data| data.module_instance.store.getMemory(data.index),
            };
        }
    }

    fn getGlobal(self: *Store, index: usize) *GlobalInstance {
        if (self.imports.globals.items.len <= index) {
            var instance_index = index - self.imports.globals.items.len;
            return &self.globals.items[instance_index];
        } else {
            var import: *GlobalImport = &self.imports.globals.items[index];
            return switch (import.data) {
                .Host => |data| data,
                .Wasm => |data| data.module_instance.store.getGlobal(data.index),
            };
        }
    }
};

pub const ModuleInstance = struct {
    allocator: std.mem.Allocator,
    stack: Stack,
    store: Store,
    module_def: *const ModuleDefinition,
    is_instantiated: bool = false,

    /// module_def is not owned by ModuleInstance - caller must ensure it memory outlives ModuleInstance
    pub fn init(module_def: *const ModuleDefinition, allocator: std.mem.Allocator) ModuleInstance {
        return ModuleInstance{
            .allocator = allocator,
            .stack = Stack.init(allocator),
            .store = Store.init(allocator),
            .module_def = module_def,
        };
    }

    pub fn deinit(self: *ModuleInstance) void {
        self.stack.deinit();
        self.store.deinit();
    }

    /// imports is not owned by ModuleInstance - caller must ensure it memory outlives ModuleInstance
    pub fn instantiate(self: *ModuleInstance, opts: struct { imports: ?[]const ModuleImports = null }) !void {
        const Helpers = struct {
            fn areLimitsCompatible(def: *const Limits, instance: *const Limits) bool {
                if (def.max != null and instance.max == null) {
                    return false;
                }

                var def_max: u32 = if (def.max) |max| max else std.math.maxInt(u32);
                var instance_max: u32 = if (instance.max) |max| max else 0;

                return def.min <= instance.min and def_max >= instance_max;
            }

            // TODO probably should change the imports search to a hashed lookup of module_name+item_name -> array of items to make this faster
            fn findImportInMultiple(comptime T: type, names: *const ImportNames, imports_or_null: ?[]const ModuleImports) UnlinkableError!*const T {
                if (imports_or_null) |_imports| {
                    for (_imports) |*module_imports| {
                        if (std.mem.eql(u8, names.module_name, module_imports.name)) {
                            switch (T) {
                                FunctionImport => {
                                    if (findImportInSingle(FunctionImport, names, module_imports)) |import| {
                                        return import;
                                    }
                                    if (findImportInSingle(TableImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(MemoryImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(GlobalImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                },
                                TableImport => {
                                    if (findImportInSingle(TableImport, names, module_imports)) |import| {
                                        return import;
                                    }
                                    if (findImportInSingle(FunctionImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(MemoryImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(GlobalImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                },
                                MemoryImport => {
                                    if (findImportInSingle(MemoryImport, names, module_imports)) |import| {
                                        return import;
                                    }
                                    if (findImportInSingle(FunctionImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(TableImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(GlobalImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                },
                                GlobalImport => {
                                    if (findImportInSingle(GlobalImport, names, module_imports)) |import| {
                                        return import;
                                    }
                                    if (findImportInSingle(FunctionImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(TableImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                    if (findImportInSingle(MemoryImport, names, module_imports)) |_| {
                                        return error.UnlinkableIncompatibleImportType;
                                    }
                                },
                                else => unreachable,
                            }
                            break;
                        }
                    }
                }

                return error.UnlinkableUnknownImport;
            }

            fn findImportInSingle(comptime T: type, names: *const ImportNames, module_imports: *const ModuleImports) ?*const T {
                var items: []const T = switch (T) {
                    FunctionImport => module_imports.functions.items,
                    TableImport => module_imports.tables.items,
                    MemoryImport => module_imports.memories.items,
                    GlobalImport => module_imports.globals.items,
                    else => unreachable,
                };

                for (items) |*item| {
                    if (std.mem.eql(u8, names.import_name, item.name)) {
                        return item;
                    }
                }

                return null;
            }
        };

        if (self.is_instantiated == false) {
            self.is_instantiated = true;
        } else {
            return AssertError.ModuleAlreadyInstantiated;
        }

        // TODO expose these options to the user
        try self.stack.allocMemory(.{
            .max_values = 1024 * 64,
            .max_labels = 1024 * 8,
            .max_frames = 256,
        });

        var store: *Store = &self.store;
        var module_def: *const ModuleDefinition = self.module_def;
        var allocator = self.allocator;

        for (module_def.imports.functions.items) |*func_import_def| {
            var import_func: *const FunctionImport = try Helpers.findImportInMultiple(FunctionImport, &func_import_def.names, opts.imports);

            const type_def: *const FunctionTypeDefinition = &module_def.types.items[func_import_def.type_index];
            const is_type_signature_eql: bool = import_func.isTypeSignatureEql(type_def);

            if (is_type_signature_eql == false) {
                return error.UnlinkableIncompatibleImportType;
            }

            try store.imports.functions.append(try import_func.dupe(allocator));
        }

        for (module_def.imports.tables.items) |*table_import_def| {
            var import_table: *const TableImport = try Helpers.findImportInMultiple(TableImport, &table_import_def.names, opts.imports);

            var is_eql: bool = undefined;
            switch (import_table.data) {
                .Host => |table_instance| {
                    is_eql = table_instance.reftype == table_import_def.reftype and
                        Helpers.areLimitsCompatible(&table_import_def.limits, &table_instance.limits);
                },
                .Wasm => |data| {
                    const table_instance: *const TableInstance = data.module_instance.store.getTable(data.index);
                    is_eql = table_instance.reftype == table_import_def.reftype and
                        Helpers.areLimitsCompatible(&table_import_def.limits, &table_instance.limits);
                },
            }

            if (is_eql == false) {
                return error.UnlinkableIncompatibleImportType;
            }

            try store.imports.tables.append(try import_table.dupe(allocator));
        }

        for (module_def.imports.memories.items) |*memory_import_def| {
            var import_memory: *const MemoryImport = try Helpers.findImportInMultiple(MemoryImport, &memory_import_def.names, opts.imports);

            var is_eql: bool = undefined;
            switch (import_memory.data) {
                .Host => |memory_instance| {
                    is_eql = Helpers.areLimitsCompatible(&memory_import_def.limits, &memory_instance.limits);
                },
                .Wasm => |data| {
                    const memory_instance: *const MemoryInstance = data.module_instance.store.getMemory(data.index);
                    is_eql = Helpers.areLimitsCompatible(&memory_import_def.limits, &memory_instance.limits);
                },
            }

            if (is_eql == false) {
                return error.UnlinkableIncompatibleImportType;
            }

            try store.imports.memories.append(try import_memory.dupe(allocator));
        }

        for (module_def.imports.globals.items) |*global_import_def| {
            var import_global: *const GlobalImport = try Helpers.findImportInMultiple(GlobalImport, &global_import_def.names, opts.imports);

            var is_eql: bool = undefined;
            switch (import_global.data) {
                .Host => |global_instance| {
                    is_eql = global_import_def.valtype == std.meta.activeTag(global_instance.value) and
                        global_import_def.mut == global_instance.mut;
                },
                .Wasm => |data| {
                    const global_instance: *const GlobalInstance = data.module_instance.store.getGlobal(data.index);
                    is_eql = global_import_def.valtype == std.meta.activeTag(global_instance.value) and
                        global_import_def.mut == global_instance.mut;
                },
            }

            if (is_eql == false) {
                return error.UnlinkableIncompatibleImportType;
            }

            try store.imports.globals.append(try import_global.dupe(allocator));
        }

        // instantiate the rest of the needed module definitions

        try store.functions.ensureTotalCapacity(module_def.functions.items.len);

        for (module_def.functions.items) |*def_func, i| {
            const func_type: *const FunctionTypeDefinition = &module_def.types.items[def_func.type_index];
            const param_types: []const ValType = func_type.getParams();

            var local_types = std.ArrayList(ValType).init(allocator);
            try local_types.ensureTotalCapacity(param_types.len + def_func.locals.items.len);
            local_types.appendSliceAssumeCapacity(param_types);
            local_types.appendSliceAssumeCapacity(def_func.locals.items);

            var f = FunctionInstance{
                .type_def_index = def_func.type_index,
                .def_index = @intCast(u32, i),
                .offset_into_instructions = def_func.offset_into_instructions,
                .local_types = local_types,
            };
            try store.functions.append(f);
        }

        try store.tables.ensureTotalCapacity(module_def.imports.tables.items.len + module_def.tables.items.len);

        for (module_def.tables.items) |*def_table| {
            var t = try TableInstance.init(def_table.reftype, def_table.limits, allocator);
            try store.tables.append(t);
        }

        try store.memories.ensureTotalCapacity(module_def.imports.memories.items.len + module_def.memories.items.len);

        for (module_def.memories.items) |*def_memory| {
            var memory = MemoryInstance.init(def_memory.limits);
            if (memory.grow(def_memory.limits.min) == false) {
                unreachable;
            }
            try store.memories.append(memory);
        }

        try store.globals.ensureTotalCapacity(module_def.imports.globals.items.len + module_def.globals.items.len);

        for (module_def.globals.items) |*def_global| {
            var global = GlobalInstance{
                .mut = def_global.mut,
                .value = try def_global.expr.resolve(store),
            };
            if (std.meta.activeTag(global.value) == .FuncRef) {
                global.value.FuncRef.module_instance = self;
            }
            try store.globals.append(global);
        }

        // iterate over elements and init the ones needed
        try store.elements.ensureTotalCapacity(module_def.elements.items.len);
        for (module_def.elements.items) |*def_elem| {
            var elem = ElementInstance{
                .refs = std.ArrayList(Val).init(allocator),
                .reftype = def_elem.reftype,
            };

            // instructions using passive elements just use the module definition's data to avoid an extra copy
            if (def_elem.mode == .Active) {
                if (store.imports.tables.items.len + store.tables.items.len <= def_elem.table_index) {
                    return error.AssertUnknownTable;
                }

                var table: *TableInstance = store.getTable(def_elem.table_index);

                var start_table_index_i32: i32 = if (def_elem.offset) |offset| (try offset.resolveTo(store, i32)) else 0;
                if (start_table_index_i32 < 0) {
                    return error.UninstantiableOutOfBoundsTableAccess;
                }

                var start_table_index = @intCast(u32, start_table_index_i32);

                if (def_elem.elems_value.items.len > 0) {
                    var elems = def_elem.elems_value.items;
                    try table.init_range_val(self, elems, @intCast(u32, elems.len), 0, start_table_index);
                } else {
                    var elems = def_elem.elems_expr.items;
                    try table.init_range_expr(self, elems, @intCast(u32, elems.len), 0, start_table_index, store);
                }
            } else if (def_elem.mode == .Passive) {
                if (def_elem.elems_value.items.len > 0) {
                    try elem.refs.resize(def_elem.elems_value.items.len);
                    var index: usize = 0;
                    while (index < elem.refs.items.len) : (index += 1) {
                        elem.refs.items[index] = def_elem.elems_value.items[index];
                        if (elem.reftype == .FuncRef) {
                            elem.refs.items[index].FuncRef.module_instance = self;
                        }
                    }
                } else {
                    try elem.refs.resize(def_elem.elems_expr.items.len);
                    var index: usize = 0;
                    while (index < elem.refs.items.len) : (index += 1) {
                        elem.refs.items[index] = try def_elem.elems_expr.items[index].resolve(store);
                        if (elem.reftype == .FuncRef) {
                            elem.refs.items[index].FuncRef.module_instance = self;
                        }
                    }
                }
            }

            store.elements.appendAssumeCapacity(elem);
        }

        for (module_def.datas.items) |*def_data| {
            // instructions using passive elements just use the module definition's data to avoid an extra copy
            if (def_data.mode == .Active) {
                var memory_index: u32 = def_data.memory_index.?;
                var memory: *MemoryInstance = store.getMemory(memory_index);

                const num_bytes: usize = def_data.bytes.items.len;
                const offset_begin: usize = try (def_data.offset.?).resolveTo(store, u32);
                const offset_end: usize = offset_begin + num_bytes;

                if (memory.mem.items.len < offset_end) {
                    return error.UninstantiableOutOfBoundsMemoryAccess;
                }

                var destination = memory.mem.items[offset_begin..offset_end];
                std.mem.copy(u8, destination, def_data.bytes.items);
            }
        }

        if (module_def.start_func_index) |func_index| {
            const params = &[0]Val{};
            var returns = &[0]Val{};

            const num_imports = module_def.imports.functions.items.len;
            if (func_index >= num_imports) {
                var instance_index = func_index - num_imports;
                try self.invokeInternal(instance_index, params, returns);
            } else {
                try self.invokeImportInternal(func_index, params, returns);
            }
        }
    }

    pub fn exports(self: *ModuleInstance, name: []const u8) !ModuleImports {
        var imports = try ModuleImports.init(name, self, self.allocator);

        for (self.module_def.exports.functions.items) |*item| {
            try imports.functions.append(FunctionImport{
                .name = try imports.allocator.dupe(u8, item.name),
                .data = .{
                    .Wasm = ImportDataWasm{
                        .module_instance = self,
                        .index = item.index,
                    },
                },
            });
        }

        for (self.module_def.exports.tables.items) |*item| {
            try imports.tables.append(TableImport{
                .name = try imports.allocator.dupe(u8, item.name),
                .data = .{
                    .Wasm = ImportDataWasm{
                        .module_instance = self,
                        .index = item.index,
                    },
                },
            });
        }

        for (self.module_def.exports.memories.items) |*item| {
            try imports.memories.append(MemoryImport{
                .name = try imports.allocator.dupe(u8, item.name),
                .data = .{
                    .Wasm = ImportDataWasm{
                        .module_instance = self,
                        .index = item.index,
                    },
                },
            });
        }

        for (self.module_def.exports.globals.items) |*item| {
            try imports.globals.append(GlobalImport{
                .name = try imports.allocator.dupe(u8, item.name),
                .data = .{
                    .Wasm = ImportDataWasm{
                        .module_instance = self,
                        .index = item.index,
                    },
                },
            });
        }

        return imports;
    }

    pub fn getGlobal(self: *ModuleInstance, global_name: []const u8) anyerror!Val {
        for (self.module_def.exports.globals.items) |*global_export| {
            if (std.mem.eql(u8, global_name, global_export.name)) {
                return self.getGlobalWithIndex(global_export.index);
            }
        }

        return error.AssertUnknownExport;
    }

    pub fn invoke(self: *ModuleInstance, func_name: []const u8, params: []const Val, returns: []Val) anyerror!void {
        for (self.module_def.exports.functions.items) |func_export| {
            if (std.mem.eql(u8, func_name, func_export.name)) {
                if (func_export.index >= self.module_def.imports.functions.items.len) {
                    var func_index: usize = func_export.index - self.module_def.imports.functions.items.len;
                    try self.invokeInternal(func_index, params, returns);
                    return;
                } else {
                    try self.invokeImportInternal(func_export.index, params, returns);
                    return;
                }
            }
        }

        for (self.store.imports.functions.items) |*func_import, i| {
            if (std.mem.eql(u8, func_name, func_import.name)) {
                try self.invokeImportInternal(i, params, returns);
            }
        }

        return error.AssertUnknownExport;
    }

    fn invokeInternal(self: *ModuleInstance, func_instance_index: usize, params: []const Val, returns: []Val) !void {
        const func: FunctionInstance = self.store.functions.items[func_instance_index];
        const func_def: FunctionDefinition = self.module_def.functions.items[func.def_index];
        const func_type: *const FunctionTypeDefinition = &self.module_def.types.items[func.type_def_index];
        const param_types: []const ValType = func_type.getParams();
        const return_types: []const ValType = func_type.getReturns();

        // pushFrame() assumes the stack already contains the params to the function, so ensure they exist
        // on the value stack
        for (params) |v| {
            try self.stack.pushValue(v);
        }

        try self.stack.pushFrame(&func, self, param_types, func.local_types.items);
        try self.stack.pushLabel(@intCast(u32, return_types.len), func_def.continuation);

        InstructionFuncs.run(func.offset_into_instructions, self.module_def.code.instructions.items.ptr, &self.stack) catch |err| {
            self.stack.popAll(); // ensure current stack state doesn't pollute future invokes
            return err;
        };

        if (returns.len > 0) {
            var index: i32 = @intCast(i32, returns.len - 1);
            while (index >= 0) {
                returns[@intCast(usize, index)] = try self.stack.popValue();
                index -= 1;
            }
        }
    }

    fn invokeImportInternal(self: *ModuleInstance, import_index: usize, params: []const Val, returns: []Val) !void {
        const func_import: *const FunctionImport = &self.store.imports.functions.items[import_index];
        switch (func_import.data) {
            .Host => |data| {
                const param_types = data.func_def.getParams();
                const return_types = data.func_def.getReturns();

                for (params) |v, i| {
                    if (std.meta.activeTag(v) != param_types[i]) {
                        return error.ValidationTypeMismatch;
                    }
                }

                if (returns.len != return_types.len) {
                    return error.ValidationTypeMismatch;
                }

                data.callback(data.userdata, params, returns);

                // validate return types
                for (returns) |val, i| {
                    if (std.meta.activeTag(val) != return_types[i]) {
                        return error.ValidationTypeMismatch;
                    }
                }
            },
            .Wasm => |data| {
                var instance: *ModuleInstance = data.module_instance;
                try instance.invoke(func_import.name, params, returns);
            },
        }
    }

    fn findFuncTypeDef(self: *ModuleInstance, index: usize) *const FunctionTypeDefinition {
        const num_imports: usize = self.store.imports.functions.items.len;
        if (index >= num_imports) {
            var local_func_index: usize = index - num_imports;
            var func_instance: *const FunctionInstance = &self.store.functions.items[local_func_index];
            var func_type_def: *const FunctionTypeDefinition = &self.module_def.types.items[func_instance.type_def_index];
            return func_type_def;
        } else {
            var import: *const FunctionImport = &self.store.imports.functions.items[index];
            var func_type_def: *const FunctionTypeDefinition = switch (import.data) {
                .Host => |data| &data.func_def,
                .Wasm => |data| data.module_instance.findFuncTypeDef(data.index),
            };
            return func_type_def;
        }
    }

    fn getGlobalWithIndex(self: *ModuleInstance, index: usize) Val {
        const num_imports: usize = self.module_def.imports.globals.items.len;
        if (index >= num_imports) {
            var local_global_index: usize = index - self.module_def.imports.globals.items.len;
            var value: Val = self.store.globals.items[local_global_index].value;
            return value;
        } else {
            var import: *const GlobalImport = &self.store.imports.globals.items[index];
            var value: Val = switch (import.data) {
                .Host => |data| data.value,
                .Wasm => |data| data.module_instance.getGlobalWithIndex(data.index),
            };
            return value;
        }
    }
};
