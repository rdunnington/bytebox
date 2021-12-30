const std = @import("std");
const builtin = @import("builtin");

pub const MalformedError = error{
    AssertInvalidMagicSignature,
};

pub const AssertError = error{
    AssertUnsupportedWasmVersion,
    AssertInvalidValType,
    AssertInvalidBytecode,
    AssertInvalidExport,
    AssertInvalidGlobalInit,
    AssertInvalidLabel,
    AssertInvalidConstantExpression,
    AssertInvalidElement,
    AssertOneTableAllowed,
    AssertTableMaxExceeded,
    AssertMultipleMemories,
    AssertMemoryMaxPagesExceeded,
    AssertMemoryInvalidMaxLimit,
    AssertUnknownTable,
    AssertUnknownType,
    AssertIncompleteInstruction,
    AssertUnknownInstruction,
    AssertTypeMismatch,
    AssertUnknownExport,
    AssertAttemptToSetImmutable,
    AssertMissingLabel,
    AssertMissingCallFrame,
    AssertLabelMismatch,
    AssertInvalidFunction,
    AssertMemoryMaxReached,
    AssertMemoryInvalidIndex,
    AssertInvalidData,
    AssertUnknownFunction,
    AssertUnknownMemory,
    AssertUnknownData,
    AssertInvalidName,
    AssertInvalidImport,
};

pub const TrapError = error{
    TrapUnreachable,
    TrapIntegerDivisionByZero,
    TrapIntegerOverflow,
    TrapIndirectCallTypeMismatch,
    TrapInvalidIntegerConversion,
    TrapOutOfBoundsMemoryAccess,
    TrapUndefinedElement,
    TrapUnknown,
};

const Opcode = enum(u16) {
    Unreachable = 0x00,
    Noop = 0x01,
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    End = 0x0B,
    Branch = 0x0C,
    Branch_If = 0x0D,
    Branch_Table = 0x0E,
    Return = 0x0F,
    Call = 0x10,
    Call_Indirect = 0x11,
    Drop = 0x1A,
    Select = 0x1B,
    Local_Get = 0x20,
    Local_Set = 0x21,
    Local_Tee = 0x22,
    Global_Get = 0x23,
    Global_Set = 0x24,
    I32_Load = 0x28,
    I64_Load = 0x29,
    F32_Load = 0x2A,
    F64_Load = 0x2B,
    I32_Load8_S = 0x2C,
    I32_Load8_U = 0x2D,
    I32_Load16_S = 0x2E,
    I32_Load16_U = 0x2F,
    I64_Load8_S = 0x30,
    I64_Load8_U = 0x31,
    I64_Load16_S = 0x32,
    I64_Load16_U = 0x33,
    I64_Load32_S = 0x34,
    I64_Load32_U = 0x35,
    I32_Store = 0x36,
    I64_Store = 0x37,
    F32_Store = 0x38,
    F64_Store = 0x39,
    I32_Store8 = 0x3A,
    I32_Store16 = 0x3B,
    I64_Store8 = 0x3C,
    I64_Store16 = 0x3D,
    I64_Store32 = 0x3E,
    Memory_Size = 0x3F,
    Memory_Grow = 0x40,
    I32_Const = 0x41,
    I64_Const = 0x42,
    F32_Const = 0x43,
    F64_Const = 0x44,
    I32_Eqz = 0x45,
    I32_Eq = 0x46,
    I32_NE = 0x47,
    I32_LT_S = 0x48,
    I32_LT_U = 0x49,
    I32_GT_S = 0x4A,
    I32_GT_U = 0x4B,
    I32_LE_S = 0x4C,
    I32_LE_U = 0x4D,
    I32_GE_S = 0x4E,
    I32_GE_U = 0x4F,
    I64_Eqz = 0x50,
    I64_Eq = 0x51,
    I64_NE = 0x52,
    I64_LT_S = 0x53,
    I64_LT_U = 0x54,
    I64_GT_S = 0x55,
    I64_GT_U = 0x56,
    I64_LE_S = 0x57,
    I64_LE_U = 0x58,
    I64_GE_S = 0x59,
    I64_GE_U = 0x5A,
    F32_EQ = 0x5B,
    F32_NE = 0x5C,
    F32_LT = 0x5D,
    F32_GT = 0x5E,
    F32_LE = 0x5F,
    F32_GE = 0x60,
    F64_EQ = 0x61,
    F64_NE = 0x62,
    F64_LT = 0x63,
    F64_GT = 0x64,
    F64_LE = 0x65,
    F64_GE = 0x66,
    I32_Clz = 0x67,
    I32_Ctz = 0x68,
    I32_Popcnt = 0x69,
    I32_Add = 0x6A,
    I32_Sub = 0x6B,
    I32_Mul = 0x6C,
    I32_Div_S = 0x6D,
    I32_Div_U = 0x6E,
    I32_Rem_S = 0x6F,
    I32_Rem_U = 0x70,
    I32_And = 0x71,
    I32_Or = 0x72,
    I32_Xor = 0x73,
    I32_Shl = 0x74,
    I32_Shr_S = 0x75,
    I32_Shr_U = 0x76,
    I32_Rotl = 0x77,
    I32_Rotr = 0x78,
    I64_Clz = 0x79,
    I64_Ctz = 0x7A,
    I64_Popcnt = 0x7B,
    I64_Add = 0x7C,
    I64_Sub = 0x7D,
    I64_Mul = 0x7E,
    I64_Div_S = 0x7F,
    I64_Div_U = 0x80,
    I64_Rem_S = 0x81,
    I64_Rem_U = 0x82,
    I64_And = 0x83,
    I64_Or = 0x84,
    I64_Xor = 0x85,
    I64_Shl = 0x86,
    I64_Shr_S = 0x87,
    I64_Shr_U = 0x88,
    I64_Rotl = 0x89,
    I64_Rotr = 0x8A,
    F32_Abs = 0x8B,
    F32_Neg = 0x8C,
    F32_Ceil = 0x8D,
    F32_Floor = 0x8E,
    F32_Trunc = 0x8F,
    F32_Nearest = 0x90,
    F32_Sqrt = 0x91,
    F32_Add = 0x92,
    F32_Sub = 0x93,
    F32_Mul = 0x94,
    F32_Div = 0x95,
    F32_Min = 0x96,
    F32_Max = 0x97,
    F32_Copysign = 0x98,
    F64_Abs = 0x99,
    F64_Neg = 0x9A,
    F64_Ceil = 0x9B,
    F64_Floor = 0x9C,
    F64_Trunc = 0x9D,
    F64_Nearest = 0x9E,
    F64_Sqrt = 0x9F,
    F64_Add = 0xA0,
    F64_Sub = 0xA1,
    F64_Mul = 0xA2,
    F64_Div = 0xA3,
    F64_Min = 0xA4,
    F64_Max = 0xA5,
    F64_Copysign = 0xA6,
    I32_Wrap_I64 = 0xA7,
    I32_Trunc_F32_S = 0xA8,
    I32_Trunc_F32_U = 0xA9,
    I32_Trunc_F64_S = 0xAA,
    I32_Trunc_F64_U = 0xAB,
    I64_Extend_I32_S = 0xAC,
    I64_Extend_I32_U = 0xAD,
    I64_Trunc_F32_S = 0xAE,
    I64_Trunc_F32_U = 0xAF,
    I64_Trunc_F64_S = 0xB0,
    I64_Trunc_F64_U = 0xB1,
    F32_Convert_I32_S = 0xB2,
    F32_Convert_I32_U = 0xB3,
    F32_Convert_I64_S = 0xB4,
    F32_Convert_I64_U = 0xB5,
    F32_Demote_F64 = 0xB6,
    F64_Convert_I32_S = 0xB7,
    F64_Convert_I32_U = 0xB8,
    F64_Convert_I64_S = 0xB9,
    F64_Convert_I64_U = 0xBA,
    F64_Promote_F32 = 0xBB,
    I32_Reinterpret_F32 = 0xBC,
    I64_Reinterpret_F64 = 0xBD,
    F32_Reinterpret_I32 = 0xBE,
    F64_Reinterpret_I64 = 0xBF,
    I32_Extend8_S = 0xC0,
    I32_Extend16_S = 0xC1,
    I64_Extend8_S = 0xC2,
    I64_Extend16_S = 0xC3,
    I64_Extend32_S = 0xC4,
    Ref_Null = 0xD0,
    Ref_Is_Null = 0xD1,
    Ref_Func = 0xD2,
    I32_Trunc_Sat_F32_S = 0xFC00,
    I32_Trunc_Sat_F32_U = 0xFC01,
    I32_Trunc_Sat_F64_S = 0xFC02,
    I32_Trunc_Sat_F64_U = 0xFC03,
    I64_Trunc_Sat_F32_S = 0xFC04,
    I64_Trunc_Sat_F32_U = 0xFC05,
    I64_Trunc_Sat_F64_S = 0xFC06,
    I64_Trunc_Sat_F64_U = 0xFC07,
    Memory_Init = 0xFC08,
    Data_Drop = 0xFC09,
    Memory_Copy = 0xFC0A,
    Memory_Fill = 0xFC0B,

    fn expectsEnd(opcode: Opcode) bool {
        return switch (opcode) {
            .Block => true,
            .Loop => true,
            .If => true,
            else => false,
        };
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

pub const Val = union(ValType) {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
    FuncRef: u32, // index into VmState.functions
    ExternRef: u32, // TODO figure out what this indexes

    const k_null_funcref: u32 = std.math.maxInt(u32);

    fn default(valtype: ValType) Val {
        return switch (valtype) {
            .I32 => Val{ .I32 = 0 },
            .I64 => Val{ .I64 = 0 },
            .F32 => Val{ .F32 = 0.0 },
            .F64 => Val{ .F64 = 0.0 },
            .FuncRef => Val{ .FuncRef = 0 },
            .ExternRef => Val{ .ExternRef = 0 },
        };
    }

    fn nullRef(valtype: ValType) !Val {
        return switch (valtype) {
            .FuncRef => Val{ .FuncRef = Val.k_null_funcref },
            .ExternRef => Val{ .ExternRef = Val.k_null_funcref },
            else => error.AssertInvalidBytecode,
        };
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

        std.debug.print("\tExpected value of type {}, but got {}\n", .{ T, val });

        return error.AssertTypeMismatch;
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
            .FuncRef => |index| index == k_null_funcref,
            .ExternRef => |index| index == k_null_funcref,
            else => unreachable,
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
};

const Label = struct {
    const k_invalid_continuation = std.math.maxInt(u32);

    blocktype: BlockTypeValue,
    continuation: u32,
    last_label_index: i32,

    fn isFirstInCallFrame(label: *const Label) bool {
        return label.last_label_index == -1;
    }
};

const CallFrame = struct {
    func: *const FunctionInstance,
    locals: std.ArrayList(Val),
};

const StackItemType = enum(u8) {
    Val,
    Label,
    Frame,
};
const StackItem = union(StackItemType) {
    Val: Val,
    Label: Label,
    Frame: CallFrame,
};

const Stack = struct {
    const Self = @This();

    fn init(allocator: std.mem.Allocator) Self {
        var self = Self{
            .stack = std.ArrayList(StackItem).init(allocator),
        };
        return self;
    }

    fn deinit(self: *Self) void {
        self.stack.deinit();
    }

    fn top(self: *const Self) !*const StackItem {
        if (self.stack.items.len > 0) {
            return &self.stack.items[self.stack.items.len - 1];
        }
        return error.OutOfBounds;
    }

    fn pop(self: *Self) !StackItem {
        if (self.stack.items.len > 0) {
            const index = self.stack.items.len - 1;
            return self.stack.orderedRemove(index);
        }
        return error.OutOfBounds;
    }

    fn topValue(self: *const Self) !Val {
        var item = try self.top();
        switch (item.*) {
            .Val => |v| return v,
            .Label => return error.AssertTypeMismatch,
            .Frame => return error.AssertTypeMismatch,
        }
    }

    fn pushValue(self: *Self, v: Val) !void {
        var item = StackItem{ .Val = v };
        try self.stack.append(item);

        // std.debug.print("\tpush value: {}\n", .{v});
    }

    fn popValue(self: *Self) !Val {
        var item = try self.pop();
        // std.debug.print("\tpop value: {}\n", .{item});
        // std.debug.print("\tstack: {any}\n", .{self.stack.items});
        switch (item) {
            .Val => |v| return v,
            .Label => return error.AssertTypeMismatch,
            .Frame => return error.AssertTypeMismatch,
        }
    }

    fn pushLabel(self: *Self, blocktype: BlockTypeValue, continuation: u32) !void {
        // std.debug.print("\t>> push label: ({}, {})\n", .{ blocktype, continuation });
        var item = StackItem{ .Label = .{
            .blocktype = blocktype,
            .continuation = continuation,
            .last_label_index = self.last_label_index,
        } };
        try self.stack.append(item);

        self.last_label_index = @intCast(i32, self.stack.items.len) - 1;
    }

    fn popLabel(self: *Self) !Label {
        var item = try self.pop();
        var label = switch (item) {
            .Val => return error.AssertTypeMismatch,
            .Label => |label| label,
            .Frame => return error.AssertTypeMismatch,
        };

        // std.debug.print("\t>> pop label: {}\n", .{label});

        self.last_label_index = label.last_label_index;

        return label;
    }

    fn topLabel(self: *const Self) *const Label {
        return &self.stack.items[@intCast(usize, self.last_label_index)].Label;
    }

    fn findLabel(self: *Self, id: u32) !*const Label {
        if (self.last_label_index < 0) {
            return error.AssertInvalidLabel;
        }

        var stack_label_id: u32 = 0;
        var label_index = self.last_label_index;
        while (label_index > 0) {
            if (stack_label_id == id) {
                return &self.stack.items[@intCast(usize, label_index)].Label;
            }
            switch (self.stack.items[@intCast(usize, label_index)]) {
                .Label => |*label| {
                    if (label.last_label_index == -1) {
                        return error.AssertInvalidLabel;
                    }
                    label_index = label.last_label_index;
                },
                else => {
                    unreachable; // last_label_index should only point to Labels
                },
            }
            stack_label_id += 1;
        }

        unreachable;
    }

    fn pushFrame(self: *Self, frame: CallFrame) !void {
        var item = StackItem{ .Frame = frame };
        try self.stack.append(item);

        // frames reset the label index since you can't jump to labels in a different function
        self.last_label_index = -1;
    }

    fn popFrame(self: *Self) !void {
        var item = try self.pop();
        switch (item) {
            .Val => return error.AssertTypeMismatch,
            .Label => return error.AssertTypeMismatch,
            .Frame => |*frame| {
                frame.locals.deinit();
            },
        }

        // have to do a linear search since we don't know what the last index was
        var item_index = self.stack.items.len;
        while (item_index > 0) {
            item_index -= 1;
            switch (self.stack.items[item_index]) {
                .Val => {},
                .Label => {
                    self.last_label_index = @intCast(i32, item_index);
                    break;
                },
                .Frame => {
                    unreachable; // frames should always be pushed with a label above them
                },
            }
        }
    }

    fn findCurrentFrame(self: *const Self) !*const CallFrame {
        var item_index: i32 = @intCast(i32, self.stack.items.len) - 1;
        while (item_index >= 0) : (item_index -= 1) {
            var index = @intCast(usize, item_index);
            if (std.meta.activeTag(self.stack.items[index]) == .Frame) {
                var frame: *const CallFrame = &self.stack.items[index].Frame;
                return frame; // why doesn't this get returned properly in the normal case??
            }
        }

        return error.AssertMissingCallFrame;
    }

    fn popI32(self: *Self) !i32 {
        var val: Val = try self.popValue();
        switch (val) {
            ValType.I32 => |value| return value,
            else => return error.AssertTypeMismatch,
        }
    }

    fn popI64(self: *Self) !i64 {
        var val: Val = try self.popValue();
        switch (val) {
            ValType.I64 => |value| return value,
            else => return error.AssertTypeMismatch,
        }
    }

    fn popF32(self: *Self) !f32 {
        var val: Val = try self.popValue();
        switch (val) {
            ValType.F32 => |value| return value,
            else => return error.AssertTypeMismatch,
        }
    }

    fn popF64(self: *Self) !f64 {
        var val: Val = try self.popValue();
        switch (val) {
            ValType.F64 => |value| return value,
            else => return error.AssertTypeMismatch,
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

    fn size(self: *const Self) usize {
        return self.stack.items.len;
    }

    fn forceClearAll(self: *Self) void {
        while (self.stack.items.len > 0) {
            var item = self.pop() catch unreachable;
            switch (item) {
                .Val => {},
                .Label => {},
                .Frame => |callframe| {
                    callframe.locals.deinit();
                },
            }
        }
        self.last_label_index = -1;
    }

    stack: std.ArrayList(StackItem),
    last_label_index: i32 = -1,
};

const Section = enum(u8) { Custom, FunctionType, Import, Function, Table, Memory, Global, Export, Start, Element, Code, Data, DataCount };

const k_function_type_sentinel_byte: u8 = 0x60;
const k_block_type_void_sentinel_byte: u8 = 0x40;

fn readFloat(comptime T: type, reader: anytype) !T {
    return switch (T) {
        f32 => @bitCast(f32, try reader.readIntLittle(u32)),
        f64 => @bitCast(f64, try reader.readIntLittle(u64)),
        else => unreachable,
    };
}

const ConstantExpression = struct {
    value: Val,

    fn decode(reader: anytype) !ConstantExpression {
        const opcode_value = try reader.readByte();
        // std.debug.print("opcode_value: 0x{X}\n", .{opcode_value});
        const opcode = @intToEnum(Opcode, opcode_value);
        const val = switch (opcode) {
            .I32_Const => Val{ .I32 = try std.leb.readILEB128(i32, reader) },
            .I64_Const => Val{ .I64 = try std.leb.readULEB128(i64, reader) },
            .F32_Const => Val{ .F32 = try readFloat(f32, reader) },
            .F64_Const => Val{ .F64 = try readFloat(f64, reader) },
            .Ref_Null => try Val.nullRef(try ValType.decode(reader)),
            .Ref_Func => Val{ .FuncRef = try std.leb.readULEB128(u32, reader) },
            // TODO handle global.get
            else => unreachable,
        };

        const end = @intToEnum(Opcode, try reader.readByte());
        if (end != .End) {
            return error.AssertInvalidConstantExpression;
        }

        return ConstantExpression{
            .value = val,
        };
    }

    fn resolve(self: ConstantExpression) !Val {
        return self.value;
    }

    fn resolveTo(self: ConstantExpression, comptime T: type) !T {
        return try self.value.get(T);
    }
};

const Limits = struct {
    min: u32,
    max: ?u32,

    fn decode(reader: anytype) !Limits {
        const has_max = try reader.readByte();
        const min = try std.leb.readULEB128(u32, reader);
        var max: ?u32 = null;

        switch (has_max) {
            0 => {},
            1 => {
                max = try std.leb.readULEB128(u32, reader);
            },
            else => return error.InvalidTableType,
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

    pub fn eql(_: Self, a: *FunctionTypeDefinition, b: *FunctionTypeDefinition) bool {
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
    locals: [ValType.count()]u32 = std.enums.directEnumArrayDefault(ValType, u32, 0, 0, .{}),
    size: u32,

    fn totalLocalCount(def: *const FunctionDefinition) u32 {
        var total: u32 = 0;
        for (def.locals) |count| {
            total += count;
        }
        return total;
    }
};

const FunctionInstance = struct {
    type_def_index: u32,
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

const GlobalMut = enum(u8) {
    Immutable = 0,
    Mutable = 1,

    fn decode(reader: anytype) !GlobalMut {
        const byte = try reader.readByte();
        const value = try std.meta.intToEnum(GlobalMut, byte);
        return value;
    }
};

const GlobalDefinition = struct {
    valtype: ValType,
    mut: GlobalMut,
    expr: ConstantExpression,
};

const GlobalInstance = struct {
    mut: GlobalMut,
    value: Val,
};

const TableDefinition = struct {
    reftype: ValType,
    limits: Limits,
};

const TableInstance = struct {
    refs: std.ArrayList(Val), // should only be reftypes
    reftype: ValType,
    limits: Limits,

    fn ensureMinSize(table: *TableInstance, size: usize) !void {
        if (table.limits.max) |max| {
            if (size > max) {
                return error.AssertTableMaxExceeded;
            }
        }

        if (table.refs.items.len < size) {
            try table.refs.resize(size);
        }
    }

    fn init_range_val(table: *TableInstance, elems: []const Val, init_length: u32, start_elem_index: u32, start_table_index: u32) !void {
        try table.ensureMinSize(start_table_index + init_length);

        if (table.refs.items.len < start_table_index + init_length) {
            return error.OutOfBounds;
        }

        if (elems.len < start_elem_index + init_length) {
            return error.OutOfBounds;
        }

        var elem_range = elems[start_elem_index .. start_elem_index + init_length];
        try table.refs.replaceRange(start_table_index, init_length, elem_range);
    }

    fn init_range_expr(table: *TableInstance, elems: []const ConstantExpression, init_length: u32, start_elem_index: u32, start_table_index: u32) !void {
        try table.ensureMinSize(start_table_index + init_length);

        if (start_table_index < 0 or table.refs.items.len < start_table_index + init_length) {
            return error.OutOfBounds;
        }

        if (start_elem_index < 0 or elems.len < start_elem_index + init_length) {
            return error.OutOfBounds;
        }

        var elem_range = elems[start_elem_index .. start_elem_index + init_length];
        var table_range = table.refs.items[start_table_index .. start_table_index + init_length];

        var index: u32 = 0;
        while (index < elem_range.len) : (index += 1) {
            var val: Val = try elem_range[index].resolve();
            if (std.meta.activeTag(val) != table.reftype) {
                return error.AssertTypeMismatch;
            }

            table_range[index] = val;
        }
    }
};

const MemoryDefinition = struct {
    limits: Limits,
};

const MemoryInstance = struct {
    const k_page_size: usize = 64 * 1024;
    const k_max_pages: usize = std.math.powi(usize, 2, 16) catch unreachable;

    limits: Limits,
    mem: []u8,
    base_addr: std.os.windows.PVOID,

    fn init(limits: Limits) MemoryInstance {
        comptime {
            std.debug.assert(builtin.os.tag == .windows);
        }

        const max_pages = if (limits.max) |max| std.math.max(1, max) else k_max_pages;

        const w = std.os.windows;
        const addr = w.VirtualAlloc(
            null,
            max_pages * k_page_size,
            w.MEM_RESERVE,
            w.PAGE_READWRITE,
        ) catch unreachable;
        var mem = @ptrCast([*]u8, addr)[0..0];

        var instance = MemoryInstance{
            .limits = Limits{ .min = 0, .max = @intCast(u32, max_pages) },
            .mem = mem,
            .base_addr = addr,
        };

        return instance;
    }

    fn deinit(self: *MemoryInstance) void {
        const w = std.os.windows;
        w.VirtualFree(@ptrCast(*c_void, self.mem.ptr), 0, w.MEM_RELEASE);
    }

    fn size(self: *MemoryInstance) usize {
        return self.mem.len / k_page_size;
    }

    fn grow(self: *MemoryInstance, num_pages: usize) bool {
        const total_pages = self.limits.min + num_pages;
        const max_pages = if (self.limits.max) |max| max else k_max_pages;

        if (total_pages > max_pages) {
            return false;
        }

        const w = std.os.windows;
        _ = w.VirtualAlloc(
            self.base_addr,
            // @ptrCast(?*c_void, self.mem.ptr),
            (self.limits.min + num_pages) * k_page_size,
            w.MEM_COMMIT,
            w.PAGE_READWRITE,
        ) catch unreachable;

        self.limits.min = @intCast(u32, total_pages);
        self.mem = @ptrCast([*]u8, self.base_addr)[0 .. total_pages * k_page_size];

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

    fn decode(reader: anytype, allocator: std.mem.Allocator) !DataDefinition {
        var data_type = try reader.readByte();
        if (data_type & ~@as(u8, 0b111) != 0) { // data_type may only be 0, 1, or 2
            return error.AssertInvalidData;
        }

        var memory_index: ?u32 = null;
        if (data_type == 0x00) {
            memory_index = 0;
        } else if (data_type == 0x02) {
            memory_index = try std.leb.readULEB128(u32, reader);
        }

        var mode = DataMode.Passive;
        var offset: ?ConstantExpression = null;
        if (data_type == 0x00 or data_type == 0x02) {
            mode = DataMode.Active;
            offset = try ConstantExpression.decode(reader);
        }

        var num_bytes = try std.leb.readULEB128(u32, reader);
        var bytes = std.ArrayList(u8).init(allocator);
        try bytes.resize(num_bytes);
        var num_read = try reader.read(bytes.items);
        if (num_read != num_bytes) {
            return error.AssertInvalidData;
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
    valtype: ValType,
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

    fn decode(reader: anytype) !MemArg {
        return MemArg{
            .alignment = try std.leb.readULEB128(u32, reader),
            .offset = try std.leb.readULEB128(u32, reader),
        };
    }
};

const CallIndirectImmediates = struct {
    type_index: u32,
    table_index: u32,
};

const BranchTableImmediates = struct {
    label_ids: std.ArrayList(u32),
    fallback_id: u32,
};

const Instruction = struct {
    const k_invalid_immediate = std.math.maxInt(u24);

    immediate: u32, // interpreted differently depending on the opcode
    opcode: Opcode,

    fn decode(reader: anytype, module: *ModuleDefinition) !Instruction {
        const Helpers = struct {
            fn decodeBlockType(_reader: anytype, _module: *ModuleDefinition) !u32 {
                var value: BlockTypeValue = undefined;

                const blocktype = try _reader.readByte();
                const valtype_or_err = ValType.bytecodeToValtype(blocktype);
                if (std.meta.isError(valtype_or_err)) {
                    if (blocktype == k_block_type_void_sentinel_byte) {
                        return 0; // the first item in the blocktype array is always void
                    } else {
                        _reader.context.pos -= 1; // move the stream backwards 1 byte to reconstruct the integer
                        var index_33bit = try std.leb.readILEB128(i33, _reader);
                        if (index_33bit < 0) {
                            return error.AssertInvalidBytecode;
                        }
                        var index: u32 = @intCast(u32, index_33bit);
                        value = BlockTypeValue{ .TypeIndex = index };
                    }
                } else {
                    var valtype: ValType = valtype_or_err catch unreachable;
                    value = BlockTypeValue{ .ValType = valtype };
                }

                for (_module.code.block_type_values.items) |*item, i| {
                    if (std.meta.eql(item.*, value)) {
                        return @intCast(u32, i);
                    }
                }

                var immediate_index = _module.code.block_type_values.items.len;
                try _module.code.block_type_values.append(value);
                return @intCast(u32, immediate_index);
            }
        };

        var byte = try reader.readByte();
        var opcode: Opcode = undefined;
        if (byte == 0xFC) {
            var byte2 = try reader.readByte();
            var extended: u16 = byte;
            extended = extended << 8;
            extended |= byte2;

            // std.debug.print(">>>>>> opcode extended_byte: 0x{X}\n", .{extended});
            opcode = @intToEnum(Opcode, extended);
        } else {
            // std.debug.print(">>>>>> opcode byte: 0x{X}\n", .{byte});
            opcode = @intToEnum(Opcode, byte);
        }
        var immediate: u32 = k_invalid_immediate;

        switch (opcode) {
            .Local_Get => {
                immediate = try std.leb.readULEB128(u32, reader); // locals index
            },
            .Local_Set => {
                immediate = try std.leb.readULEB128(u32, reader); // locals index
            },
            .Local_Tee => {
                immediate = try std.leb.readULEB128(u32, reader); // locals index
            },
            .Global_Get => {
                immediate = try std.leb.readULEB128(u32, reader); // locals index
            },
            .Global_Set => {
                immediate = try std.leb.readULEB128(u32, reader); // locals index
            },
            .I32_Const => {
                var value = try std.leb.readILEB128(i32, reader);
                immediate = @bitCast(u32, value);
            },
            .I64_Const => {
                var value = try std.leb.readILEB128(i64, reader);

                for (module.code.i64_const.items) |item, i| {
                    if (value == item) {
                        immediate = @intCast(u32, i);
                    }
                }

                if (immediate == k_invalid_immediate) {
                    immediate = @intCast(u32, module.code.i64_const.items.len);
                    try module.code.i64_const.append(value);
                }
            },
            .F32_Const => {
                var value = try readFloat(f32, reader);
                immediate = @bitCast(u32, value);
            },
            .F64_Const => {
                var value = try readFloat(f64, reader);

                for (module.code.f64_const.items) |item, i| {
                    if (value == item) {
                        immediate = @intCast(u32, i);
                        break;
                    }
                }

                if (immediate == k_invalid_immediate) {
                    immediate = @intCast(u32, module.code.f64_const.items.len);
                    try module.code.f64_const.append(value);
                }
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
                immediate = try std.leb.readULEB128(u32, reader); // label id
            },
            .Branch_If => {
                immediate = try std.leb.readULEB128(u32, reader); // label id
            },
            .Branch_Table => {
                const table_length = try std.leb.readULEB128(u32, reader);

                var label_ids = std.ArrayList(u32).init(module.allocator);
                try label_ids.ensureTotalCapacity(table_length);

                var index: u32 = 0;
                while (index < table_length) : (index += 1) {
                    var id = try std.leb.readULEB128(u32, reader);
                    label_ids.addOneAssumeCapacity().* = id;
                }
                var fallback_id = try std.leb.readULEB128(u32, reader);

                var branch_table = BranchTableImmediates{
                    .label_ids = label_ids,
                    .fallback_id = fallback_id,
                };

                for (module.code.branch_table.items) |*item, i| {
                    if (item.fallback_id == branch_table.fallback_id) {
                        if (std.mem.eql(u32, item.label_ids.items, branch_table.label_ids.items)) {
                            immediate = @intCast(u32, i);
                            break;
                        }
                    }
                }

                if (immediate == k_invalid_immediate) {
                    immediate = @intCast(u32, module.code.branch_table.items.len);
                    try module.code.branch_table.append(branch_table);
                }
            },
            .Call => {
                immediate = try std.leb.readULEB128(u32, reader); // function index
            },
            .Call_Indirect => {
                var call_indirect_immedates = CallIndirectImmediates{
                    .type_index = try std.leb.readULEB128(u32, reader),
                    .table_index = try std.leb.readULEB128(u32, reader),
                };

                for (module.code.call_indirect.items) |*item, i| {
                    if (std.meta.eql(item.*, call_indirect_immedates)) {
                        immediate = @intCast(u32, i);
                        break;
                    }
                }

                if (immediate == k_invalid_immediate) {
                    immediate = @intCast(u32, module.code.call_indirect.items.len);
                    try module.code.call_indirect.append(call_indirect_immedates);
                }
            },
            .I32_Load => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Load => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .F32_Load => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .F64_Load => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I32_Load8_S => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I32_Load8_U => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I32_Load16_S => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I32_Load16_U => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Load8_S => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Load8_U => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Load16_S => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Load16_U => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Load32_S => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Load32_U => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I32_Store => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Store => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .F32_Store => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .F64_Store => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I32_Store8 => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I32_Store16 => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Store8 => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Store16 => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .I64_Store32 => {
                var memarg = try MemArg.decode(reader);
                immediate = memarg.offset;
            },
            .Memory_Size => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.AssertInvalidBytecode;
                }
            },
            .Memory_Grow => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.AssertInvalidBytecode;
                }
            },
            .Memory_Init => {
                immediate = try std.leb.readULEB128(u32, reader); // dataidx
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.AssertInvalidBytecode;
                }
            },
            .Ref_Null => {
                var valtype = try ValType.decode(reader);
                if (valtype.isRefType() == false) {
                    return error.AssertInvalidBytecode;
                }

                immediate = @enumToInt(valtype);
            },
            .Ref_Func => {
                immediate = try std.leb.readULEB128(u32, reader); // funcidx
            },
            .Data_Drop => {
                immediate = try std.leb.readULEB128(u32, reader); // dataidx
            },
            .Memory_Copy => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.AssertInvalidBytecode;
                }
                reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.AssertInvalidBytecode;
                }
            },
            .Memory_Fill => {
                var reserved = try reader.readByte();
                if (reserved != 0x00) {
                    return error.AssertInvalidBytecode;
                }
            },
            else => {},
        }

        var inst = Instruction{
            .opcode = opcode,
            .immediate = immediate,
        };

        switch (inst.opcode) {
            .Noop => {}, // no need to emit noops since they don't do anything
            else => try module.code.instructions.append(inst),
        }

        return inst;
    }
};

const ModuleValidator = struct {
    fn validateMemoryIndex(module: *const ModuleDefinition) !void {
        if (module.memories.items.len < 1) {
            return error.AssertUnknownMemory;
        }
    }

    fn validateDataIndex(index: u32, module: *const ModuleDefinition) !void {
        if (module.data_count) |count| {
            if (count <= index) {
                return error.AssertUnknownData;
            }
        }
    }

    fn validate(instruction: Instruction, module: *const ModuleDefinition) !void {
        switch (instruction.opcode) {
            .Memory_Init => {
                try validateMemoryIndex(module);
                try validateDataIndex(instruction.immediate, module);
            },
            .Data_Drop => {
                try validateDataIndex(instruction.immediate, module);
            },
            .Memory_Copy => {
                try validateMemoryIndex(module);
            },
            .Memory_Fill => {
                try validateMemoryIndex(module);
            },
            else => {},
        }
    }
};

pub const ModuleDefinition = struct {
    const Code = struct {
        instructions: std.ArrayList(Instruction),

        // Instruction.immediate indexes these arrays depending on the opcode
        block_type_values: std.ArrayList(BlockTypeValue),
        call_indirect: std.ArrayList(CallIndirectImmediates),
        branch_table: std.ArrayList(BranchTableImmediates),
        i64_const: std.ArrayList(i64),
        f64_const: std.ArrayList(f64),
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
    start_func_index: ?u32 = null,
    data_count: ?u32 = null,

    function_continuations: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList
    label_continuations: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList
    if_to_else_offsets: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList

    pub fn init(wasm: []const u8, allocator: std.mem.Allocator) !ModuleDefinition {
        var module = ModuleDefinition{
            .allocator = allocator,
            .code = Code{
                .instructions = std.ArrayList(Instruction).init(allocator),
                .block_type_values = std.ArrayList(BlockTypeValue).init(allocator),
                .call_indirect = std.ArrayList(CallIndirectImmediates).init(allocator),
                .branch_table = std.ArrayList(BranchTableImmediates).init(allocator),
                .i64_const = std.ArrayList(i64).init(allocator),
                .f64_const = std.ArrayList(f64).init(allocator),
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

            .function_continuations = std.AutoHashMap(u32, u32).init(allocator),
            .label_continuations = std.AutoHashMap(u32, u32).init(allocator),
            .if_to_else_offsets = std.AutoHashMap(u32, u32).init(allocator),
        };
        errdefer module.deinit();

        // first block type is always void for quick decoding
        try module.code.block_type_values.append(BlockTypeValue{ .Void = {} });

        const DecodeHelpers = struct {
            fn readRefType(valtype: ValType, reader: anytype) !Val {
                switch (valtype) {
                    .FuncRef => {
                        const func_index = try std.leb.readULEB128(u32, reader);
                        return Val{ .FuncRef = func_index };
                    },
                    .ExternRef => {
                        unreachable; // TODO
                    },
                    else => unreachable,
                }
            }

            fn readName(reader: anytype, _allocator: std.mem.Allocator) ![]const u8 {
                const name_length = try std.leb.readULEB128(u32, reader);

                var name: []u8 = try _allocator.alloc(u8, name_length);
                errdefer _allocator.free(name);
                var read_length = try reader.read(name);
                if (read_length != name_length) {
                    return error.AssertInvalidName;
                }

                return name;
            }
        };

        var stream = std.io.fixedBufferStream(wasm);
        var reader = stream.reader();

        // wasm header
        {
            const magic = try reader.readIntBig(u32);
            if (magic != 0x0061736D) {
                return error.AssertInvalidMagicSignature;
            }
            const version = try reader.readIntLittle(u32);
            if (version != 1) {
                return error.AssertUnsupportedWasmVersion;
            }
        }

        while (stream.pos < stream.buffer.len) {
            const section_id: Section = @intToEnum(Section, try reader.readByte());
            const size_bytes: usize = try std.leb.readULEB128(u32, reader);

            // std.debug.print("parseWasm: section: {}: {} bytes, pos: {}\n", .{section_id, size_bytes, stream.pos});

            switch (section_id) {
                .FunctionType => {
                    const num_types = try std.leb.readULEB128(u32, reader);

                    try module.types.ensureTotalCapacity(num_types);

                    var types_index: u32 = 0;
                    while (types_index < num_types) : (types_index += 1) {
                        const sentinel = try reader.readByte();
                        if (sentinel != k_function_type_sentinel_byte) {
                            return error.AssertInvalidBytecode;
                        }

                        const num_params = try std.leb.readULEB128(u32, reader);

                        var func = FunctionTypeDefinition{ .num_params = num_params, .types = std.ArrayList(ValType).init(allocator) };
                        errdefer func.types.deinit();

                        var params_left = num_params;
                        while (params_left > 0) {
                            params_left -= 1;

                            var param_type = try ValType.decode(reader);
                            try func.types.append(param_type);
                        }

                        const num_returns = try std.leb.readULEB128(u32, reader);
                        var returns_left = num_returns;
                        while (returns_left > 0) {
                            returns_left -= 1;

                            var return_type = try ValType.decode(reader);
                            try func.types.append(return_type);
                        }

                        try module.types.append(func);
                    }
                },
                .Import => {
                    const num_imports = try std.leb.readULEB128(u32, reader);

                    var import_index: u32 = 0;
                    while (import_index < num_imports) : (import_index += 1) {
                        var module_name: []const u8 = try DecodeHelpers.readName(reader, allocator);
                        errdefer allocator.free(module_name);

                        var import_name: []const u8 = try DecodeHelpers.readName(reader, allocator);
                        errdefer allocator.free(module_name);

                        const names = ImportNames{
                            .module_name = module_name,
                            .import_name = import_name,
                        };

                        const desc = try reader.readByte();
                        switch (desc) {
                            0x00 => {
                                const type_index = try std.leb.readULEB128(u32, reader);
                                try module.imports.functions.append(FunctionImportDefinition{
                                    .names = names,
                                    .type_index = type_index,
                                });
                            },
                            0x01 => {
                                const valtype = try ValType.decode(reader);
                                if (valtype.isRefType() == false) {
                                    return error.AssertInvalidImport;
                                }
                                const limits = try Limits.decode(reader);
                                try module.imports.tables.append(TableImportDefinition{
                                    .names = names,
                                    .valtype = valtype,
                                    .limits = limits,
                                });
                            },
                            0x02 => {
                                const limits = try Limits.decode(reader);
                                try module.imports.memories.append(MemoryImportDefinition{
                                    .names = names,
                                    .limits = limits,
                                });
                            },
                            0x03 => {
                                const valtype = try ValType.decode(reader);
                                const mut = try GlobalMut.decode(reader);

                                try module.imports.globals.append(GlobalImportDefinition{
                                    .names = names,
                                    .valtype = valtype,
                                    .mut = mut,
                                });
                            },
                            else => return error.AssertInvalidImport,
                        }
                    }
                },
                .Function => {
                    const num_funcs = try std.leb.readULEB128(u32, reader);

                    try module.functions.ensureTotalCapacity(num_funcs);

                    var func_index: u32 = 0;
                    while (func_index < num_funcs) : (func_index += 1) {
                        var func = FunctionDefinition{
                            .type_index = try std.leb.readULEB128(u32, reader),

                            // we'll fix these up later when we find them in the Code section
                            .offset_into_instructions = 0,
                            .size = 0,
                        };

                        try module.functions.append(func);
                    }
                },
                .Table => {
                    const num_tables = try std.leb.readULEB128(u32, reader);
                    if (num_tables > 1) {
                        return error.AssertOneTableAllowed;
                    }

                    try module.tables.ensureTotalCapacity(num_tables);

                    var table_index: u32 = 0;
                    while (table_index < num_tables) : (table_index += 1) {
                        const valtype = try ValType.decode(reader);
                        if (valtype.isRefType() == false) {
                            return error.InvalidTableType;
                        }

                        const limits = try Limits.decode(reader);

                        try module.tables.append(TableDefinition{
                            // .refs = std.ArrayList(Val).init(allocator),
                            .reftype = valtype,
                            .limits = limits,
                        });
                    }
                },
                .Memory => {
                    const num_memories = try std.leb.readULEB128(u32, reader);

                    if (num_memories > 1) {
                        return error.AssertMultipleMemories;
                    }

                    try module.memories.ensureTotalCapacity(num_memories);

                    var memory_index: u32 = 0;
                    while (memory_index < num_memories) : (memory_index += 1) {
                        var limits = try Limits.decode(reader);
                        if (limits.max) |max| {
                            if (max < limits.min) {
                                return error.AssertMemoryInvalidMaxLimit;
                            }
                            if (max > MemoryInstance.k_max_pages) {
                                return error.AssertMemoryMaxPagesExceeded;
                            }
                        }

                        var def = MemoryDefinition{
                            .limits = limits,
                        };
                        try module.memories.append(def);
                    }
                },
                .Global => {
                    const num_globals = try std.leb.readULEB128(u32, reader);

                    try module.globals.ensureTotalCapacity(num_globals);

                    var global_index: u32 = 0;
                    while (global_index < num_globals) : (global_index += 1) {
                        var valtype = try ValType.decode(reader);
                        var mut = try GlobalMut.decode(reader);

                        // TODO validate global references are for imports only
                        const expr = try ConstantExpression.decode(reader);

                        try module.globals.append(GlobalDefinition{
                            .valtype = valtype,
                            .expr = expr,
                            .mut = mut,
                        });
                    }
                },
                .Export => {
                    const num_exports = try std.leb.readULEB128(u32, reader);

                    var export_index: u32 = 0;
                    while (export_index < num_exports) : (export_index += 1) {
                        var name: []const u8 = try DecodeHelpers.readName(reader, allocator);
                        errdefer allocator.free(name);

                        const exportType = @intToEnum(ExportType, try reader.readByte());
                        const item_index = try std.leb.readULEB128(u32, reader);
                        const def = ExportDefinition{ .name = name, .index = item_index };

                        switch (exportType) {
                            .Function => {
                                if (item_index >= module.functions.items.len) {
                                    return error.AssertInvalidExport;
                                }
                                try module.exports.functions.append(def);
                            },
                            .Table => {
                                if (item_index >= module.tables.items.len) {
                                    return error.AssertInvalidExport;
                                }
                                try module.exports.tables.append(def);
                            },
                            .Memory => {
                                if (item_index >= module.memories.items.len) {
                                    return error.AssertInvalidExport;
                                }
                                try module.exports.memories.append(def);
                            },
                            .Global => {
                                if (item_index >= module.globals.items.len) {
                                    return error.AssertInvalidExport;
                                }
                                try module.exports.globals.append(def);
                            },
                        }
                    }
                },
                .Start => {
                    module.start_func_index = try std.leb.readULEB128(u32, reader);

                    if (module.functions.items.len <= module.start_func_index.?) {
                        return error.AssertUnknownFunction;
                    }
                },
                .Element => {
                    const ElementHelpers = struct {
                        fn readElemsVal(elems: *std.ArrayList(Val), valtype: ValType, _reader: anytype) !void {
                            const num_elems = try std.leb.readULEB128(u32, _reader);
                            try elems.ensureTotalCapacity(num_elems);

                            var elem_index: u32 = 0;
                            while (elem_index < num_elems) : (elem_index += 1) {
                                try elems.append(try DecodeHelpers.readRefType(valtype, _reader));
                            }
                        }

                        fn readElemsExpr(elems: *std.ArrayList(ConstantExpression), _reader: anytype) !void {
                            const num_elems = try std.leb.readULEB128(u32, _reader);
                            try elems.ensureTotalCapacity(num_elems);

                            var elem_index: u32 = 0;
                            while (elem_index < num_elems) : (elem_index += 1) {
                                var expr = try ConstantExpression.decode(_reader);
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

                    const num_segments = try std.leb.readULEB128(u32, reader);

                    try module.elements.ensureTotalCapacity(num_segments);

                    var segment_index: u32 = 0;
                    while (segment_index < num_segments) : (segment_index += 1) {
                        var flags = try reader.readByte();

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
                                def.offset = try ConstantExpression.decode(reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader);
                            },
                            0x01 => {
                                def.mode = .Passive;
                                try ElementHelpers.readNullElemkind(reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader);
                            },
                            0x02 => {
                                def.table_index = try std.leb.readULEB128(u32, reader);
                                def.offset = try ConstantExpression.decode(reader);
                                def.reftype = try ValType.decode(reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader);
                            },
                            0x03 => {
                                def.mode = .Declarative;
                                try ElementHelpers.readNullElemkind(reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, reader);
                            },
                            0x04 => {
                                def.offset = try ConstantExpression.decode(reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader);
                            },
                            0x05 => {
                                def.mode = .Passive;
                                def.reftype = try ValType.decode(reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader);
                            },
                            0x06 => {
                                def.table_index = try std.leb.readULEB128(u32, reader);
                                def.offset = try ConstantExpression.decode(reader);
                                def.reftype = try ValType.decode(reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader);
                            },
                            0x07 => {
                                def.mode = .Declarative;
                                def.reftype = try ValType.decode(reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, reader);
                            },
                            else => unreachable,
                        }

                        try module.elements.append(def);
                    }
                },
                .Code => {
                    const BlockData = struct {
                        offset: u32,
                        opcode: Opcode,
                    };
                    var block_stack = std.ArrayList(BlockData).init(allocator);
                    defer block_stack.deinit();

                    const num_codes = try std.leb.readULEB128(u32, reader);
                    var code_index: u32 = 0;
                    while (code_index < num_codes) {
                        // std.debug.print(">>> parsing code index {}\n", .{code_index});
                        const code_size = try std.leb.readULEB128(u32, reader);
                        const code_begin_pos = stream.pos;

                        var def = &module.functions.items[code_index];
                        def.offset_into_instructions = @intCast(u32, code_begin_pos);
                        def.size = code_size;

                        const num_locals = try std.leb.readULEB128(u32, reader);
                        var locals_index: u32 = 0;
                        while (locals_index < num_locals) {
                            locals_index += 1;
                            const n = try std.leb.readULEB128(u32, reader);
                            const local_type = try ValType.decode(reader);
                            def.locals[@enumToInt(local_type)] = n;
                        }

                        const instruction_begin_offset = @intCast(u32, module.code.instructions.items.len);
                        module.functions.items[code_index].offset_into_instructions = instruction_begin_offset;
                        try block_stack.append(BlockData{
                            .offset = instruction_begin_offset,
                            .opcode = .Block,
                        });

                        var parsing_code = true;
                        while (parsing_code) {
                            const parsing_offset = @intCast(u32, module.code.instructions.items.len);

                            var instruction = try Instruction.decode(reader, &module);
                            try ModuleValidator.validate(instruction, &module);

                            if (instruction.opcode.expectsEnd()) {
                                try block_stack.append(BlockData{
                                    .offset = parsing_offset,
                                    .opcode = instruction.opcode,
                                });
                            } else if (instruction.opcode == .Else) {
                                const block: *const BlockData = &block_stack.items[block_stack.items.len - 1];
                                try module.if_to_else_offsets.putNoClobber(block.offset, parsing_offset);
                                instruction.immediate = module.code.instructions.items[block.offset].immediate; // the else gets the matching if's immediate index
                            } else if (instruction.opcode == .End) {
                                const block: BlockData = block_stack.orderedRemove(block_stack.items.len - 1);
                                if (block_stack.items.len == 0) {
                                    // std.debug.print("found the end\n", .{});
                                    parsing_code = false;

                                    try module.function_continuations.putNoClobber(block.offset, parsing_offset);
                                    block_stack.clearRetainingCapacity();
                                    // std.debug.print("adding function continuation for offset {}: {}\n", .{block.offset, parsing_offset});
                                } else {
                                    if (block.opcode == .Loop) {
                                        try module.label_continuations.putNoClobber(block.offset, block.offset);
                                        // std.debug.print("adding loop continuation for offset {}: {}\n", .{ block.offset, block.offset });
                                    } else {
                                        try module.label_continuations.putNoClobber(block.offset, parsing_offset);
                                        // std.debug.print("adding block continuation for offset {}: {}\n", .{block.offset, parsing_offset});

                                        var else_offset_or_null = module.if_to_else_offsets.get(block.offset);
                                        if (else_offset_or_null) |else_offset| {
                                            try module.label_continuations.putNoClobber(else_offset, parsing_offset);
                                            // std.debug.print("adding block continuation for offset {}: {}\n", .{else_offset, parsing_offset});
                                        }
                                    }
                                }
                            }
                        }

                        const code_actual_size = stream.pos - code_begin_pos;
                        if (code_actual_size != code_size) {
                            // std.debug.print("expected code_size: {}, code_actual_size: {}\n", .{code_size, code_actual_size});
                            // std.debug.print("stream.pos: {}, code_begin_pos: {}, code_begin_pos + code_size: {}\n", .{stream.pos, code_begin_pos, code_begin_pos + code_size});
                            return error.AssertInvalidBytecode;
                        }

                        code_index += 1;
                    }
                },
                .Data => {
                    const num_datas = try std.leb.readULEB128(u32, reader);
                    var data_index: u32 = 0;
                    while (data_index < num_datas) : (data_index += 1) {
                        var data = try DataDefinition.decode(reader, allocator);
                        try module.datas.append(data);
                    }
                },
                .DataCount => {
                    module.data_count = try std.leb.readULEB128(u32, reader);
                    try module.datas.ensureTotalCapacity(module.data_count.?);
                },
                else => {
                    std.debug.print("Skipping module section {}\n", .{section_id});
                    try stream.seekBy(@intCast(i64, size_bytes));
                },
            }
        }

        return module;
    }

    pub fn deinit(self: *ModuleDefinition) void {
        self.code.instructions.deinit();
        self.code.block_type_values.deinit();
        self.code.call_indirect.deinit();
        for (self.code.branch_table.items) |*item| {
            item.label_ids.deinit();
        }
        self.code.i64_const.deinit();
        self.code.f64_const.deinit();
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

        self.function_continuations.deinit();
        self.label_continuations.deinit();
        self.if_to_else_offsets.deinit();
    }
};

const ImportType = enum(u8) {
    Host,
    Wasm,
};

const HostFunctionCallback = fn (userdata: ?*c_void, params: []const Val, returns: []Val) void;

const HostFunction = struct {
    userdata: ?*c_void,
    param_types: std.ArrayList(ValType),
    callback: HostFunctionCallback,
};

pub const FunctionImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: HostFunction,
        Wasm: u32, // index into function instances
    },
};

pub const TableImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: *TableInstance,
        Wasm: u32, // index into tables
    },
};

pub const MemoryImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: *MemoryInstance,
        Wasm: void, // no need for an index since there can only be 1 instance
    },
};

pub const GlobalImport = struct {
    name: []const u8,
    data: union(ImportType) {
        Host: *GlobalInstance,
        Wasm: u32, // index into globals
    },
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

    pub fn addHostFunction(self: *ModuleImports, name: []const u8, userdata: ?*c_void, param_types: []const ValType, callback: HostFunctionCallback) !void {
        std.debug.assert(self.instance == null); // cannot add host functions to an imports that is intended to be bound to a module instance

        var type_list = std.ArrayList(ValType).init(self.allocator);
        try type_list.appendSlice(param_types);

        try self.functions.append(FunctionImport{
            .name = try self.allocator.dupe(u8, name),
            .data = .{
                .Host = HostFunction{
                    .userdata = userdata,
                    .param_types = type_list,
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
                .Host => |h| h.param_types.deinit(),
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

    module_def: *const ModuleDefinition, // temp

    fn init(module_def: *const ModuleDefinition, _: []const ModuleImports, allocator: std.mem.Allocator) !Store {
        var store = Store{
            .functions = std.ArrayList(FunctionInstance).init(allocator),
            .tables = std.ArrayList(TableInstance).init(allocator),
            .memories = std.ArrayList(MemoryInstance).init(allocator),
            .globals = std.ArrayList(GlobalInstance).init(allocator),
            .elements = std.ArrayList(ElementInstance).init(allocator),

            .module_def = module_def,
        };
        errdefer store.deinit();

        try store.functions.ensureTotalCapacity(module_def.imports.functions.items.len + module_def.functions.items.len);
        for (module_def.imports.functions.items) |_| {
            var f = FunctionInstance{
                .type_def_index = 0,
                .offset_into_instructions = 0,
                .local_types = std.ArrayList(ValType).init(allocator),
            };
            try store.functions.append(f);
        }
        for (module_def.functions.items) |*def_func| {
            const func_type: *const FunctionTypeDefinition = &module_def.types.items[def_func.type_index];
            const param_types: []const ValType = func_type.getParams();

            var local_types = std.ArrayList(ValType).init(allocator);
            try local_types.resize(param_types.len + def_func.totalLocalCount());

            for (param_types) |valtype, i| {
                local_types.items[i] = valtype;
            }

            var locals_index: usize = param_types.len;
            for (def_func.locals) |count, valtype_as_int| {
                var index: u32 = 0;
                while (index < count) : (index += 1) {
                    local_types.items[locals_index] = @intToEnum(ValType, valtype_as_int);
                    locals_index += 1;
                }
            }

            var f = FunctionInstance{
                .type_def_index = def_func.type_index,
                .offset_into_instructions = def_func.offset_into_instructions,
                .local_types = local_types,
            };
            try store.functions.append(f);
        }

        try store.tables.ensureTotalCapacity(module_def.imports.tables.items.len + module_def.tables.items.len);
        for (module_def.imports.tables.items) |_| {
            // stub
            var t = TableInstance{
                .refs = std.ArrayList(Val).init(allocator),
                .reftype = ValType.FuncRef,
                .limits = Limits{
                    .min = 0,
                    .max = null,
                },
            };
            try store.tables.append(t);
        }
        for (module_def.tables.items) |*def_table| {
            var t = TableInstance{
                .refs = std.ArrayList(Val).init(allocator),
                .reftype = def_table.reftype,
                .limits = def_table.limits,
            };
            try t.refs.ensureTotalCapacity(def_table.limits.min);
            try store.tables.append(t);
        }

        try store.memories.ensureTotalCapacity(module_def.imports.memories.items.len + module_def.memories.items.len);
        for (module_def.imports.memories.items) |_| {
            var m = MemoryInstance.init(Limits{
                .min = 0,
                .max = null,
            });
            try store.memories.append(m);
        }
        for (module_def.memories.items) |*def_memory| {
            var memory = MemoryInstance.init(def_memory.limits);
            if (def_memory.limits.min > 0) {
                if (memory.grow(def_memory.limits.min) == false) {
                    return error.OutOfMemory;
                }
            }
            try store.memories.append(memory);
        }

        try store.globals.ensureTotalCapacity(module_def.imports.globals.items.len + module_def.globals.items.len);
        for (module_def.imports.globals.items) |_| {
            var g = GlobalInstance{ .mut = GlobalMut.Immutable, .value = Val{
                .I32 = 0,
            } };
            try store.globals.append(g);
        }
        for (module_def.globals.items) |*def_global| {
            var global = GlobalInstance{
                .mut = def_global.mut,
                .value = try def_global.expr.resolve(),
            };
            try store.globals.append(global);
        }

        // iterate over elements and init the ones needed
        for (module_def.elements.items) |*def_elem| {
            if (store.tables.items.len <= def_elem.table_index) {
                return error.AssertUnknownTable;
            }

            var table: *TableInstance = &store.tables.items[def_elem.table_index];

            if (def_elem.mode == .Active) {
                var start_table_index_i32: i32 = if (def_elem.offset) |offset| (try offset.resolveTo(i32)) else 0;
                if (start_table_index_i32 < 0) {
                    return error.OutOfBounds;
                }

                var start_table_index = @intCast(u32, start_table_index_i32);

                if (def_elem.elems_value.items.len > 0) {
                    var elems = def_elem.elems_value.items;
                    try table.init_range_val(elems, @intCast(u32, elems.len), 0, start_table_index);
                } else {
                    var elems = def_elem.elems_expr.items;
                    try table.init_range_expr(elems, @intCast(u32, elems.len), 0, start_table_index);
                }
            } else {
                // TODO
            }
        }

        for (module_def.datas.items) |*def_data| {
            if (def_data.mode == .Active) {
                var memory_index: u32 = def_data.memory_index.?;
                if (module_def.memories.items.len <= memory_index) {
                    return error.AssertUnknownMemory;
                }

                var memory: *MemoryInstance = &store.memories.items[memory_index];

                const num_bytes: usize = def_data.bytes.items.len;
                if (num_bytes > 0) {
                    const offset_begin: usize = try (def_data.offset.?).resolveTo(u32);
                    const offset_end: usize = offset_begin + num_bytes;
                    // std.debug.print("memory.limits: {}, offset_begin: {}, num_bytes: {}, offset_end: {}\n", .{ memory.limits, offset_begin, num_bytes, offset_end });

                    try memory.ensureMinSize(offset_end);

                    var destination = memory.mem[offset_begin..offset_end];
                    std.mem.copy(u8, destination, def_data.bytes.items);
                }
            }
        }

        return store;
    }

    fn deinit(self: *Store) void {
        self.functions.deinit();

        for (self.tables.items) |*item| {
            item.refs.deinit();
        }
        self.tables.deinit();

        for (self.memories.items) |*item| {
            item.deinit();
        }
        self.memories.deinit();

        self.globals.deinit();
        self.elements.deinit();
        // self.datas.deinit();
    }
};

pub const ModuleInstance = struct {
    allocator: std.mem.Allocator,
    stack: Stack,
    store: Store,
    module_def: *const ModuleDefinition,

    pub fn init(module_def: *const ModuleDefinition, imports: []const ModuleImports, allocator: std.mem.Allocator) !ModuleInstance {
        var inst = ModuleInstance{
            .allocator = allocator,
            .stack = Stack.init(allocator),
            .store = try Store.init(module_def, imports, allocator),
            .module_def = module_def,
        };
        errdefer inst.deinit();

        if (module_def.start_func_index) |func_index| {
            const params = [0]Val{};
            var returns = [0]Val{};
            try inst.invoke_internal(func_index + module_def.imports.functions.items.len, &params, &returns);
        }

        return inst;
    }

    pub fn deinit(self: *ModuleInstance) void {
        self.stack.deinit();
        self.store.deinit();
    }

    pub fn invoke(self: *ModuleInstance, func_name: []const u8, params: []const Val, returns: []Val) !void {
        for (self.module_def.exports.functions.items) |func_export| {
            if (std.mem.eql(u8, func_name, func_export.name)) {
                const func_index: usize = func_export.index + self.module_def.imports.functions.items.len;
                try self.invoke_internal(func_index, params, returns);
                return;
            }
        }
        return error.AssertUnknownExport;
    }

    fn invoke_internal(self: *ModuleInstance, func_instance_index: usize, params: []const Val, returns: []Val) !void {
        const func: FunctionInstance = self.store.functions.items[func_instance_index];
        const func_type_params: []const ValType = self.module_def.types.items[func.type_def_index].getParams();

        if (params.len != func_type_params.len) {
            // std.debug.print("params.len: {}, func_type_params.len: {}\n", .{params.len, func_type_params.len});
            // std.debug.print("params: {s}, func_type_params: {s}\n", .{params, func_type_params});
            return error.AssertTypeMismatch;
        }

        for (params) |param, i| {
            if (std.meta.activeTag(param) != func_type_params[i]) {
                return error.AssertTypeMismatch;
            }
        }

        var locals = std.ArrayList(Val).init(self.allocator); // gets deinited when popFrame() is called
        try locals.resize(func.local_types.items.len);
        for (params) |v, i| {
            locals.items[i] = v;
        }

        // initialize the rest of the locals according to the type of the local
        var locals_index = params.len;
        while (locals_index < locals.items.len) : (locals_index += 1) {
            const valtype: ValType = func.local_types.items[locals_index];
            locals.items[locals_index] = Val.default(valtype);
        }

        // TODO move function continuation data into FunctionDefinition
        var function_continuation = self.module_def.function_continuations.get(func.offset_into_instructions) orelse return error.AssertInvalidFunction;

        try self.stack.pushFrame(CallFrame{
            .func = &func,
            .locals = locals,
        });
        try self.stack.pushLabel(BlockTypeValue{ .TypeIndex = func.type_def_index }, function_continuation);
        self.executeWasm(self.module_def.code.instructions.items, func.offset_into_instructions) catch |err| {
            self.stack.forceClearAll(); // ensure current stack state doesn't pollute future invokes
            return err;
        };

        if (self.stack.size() != returns.len) {
            std.debug.print("stack size: {}, returns.len: {}\n", .{ self.stack.size(), returns.len });
            return error.AssertTypeMismatch;
        }

        if (returns.len > 0) {
            var index: i32 = @intCast(i32, returns.len - 1);
            while (index >= 0) {
                // std.debug.print("stack size: {}, index: {}\n", .{self.stack.size(), index});
                returns[@intCast(usize, index)] = try self.stack.popValue();
                index -= 1;
            }
        }
    }

    fn executeWasm(self: *ModuleInstance, instructions: []const Instruction, root_offset: u32) !void {
        const Helpers = struct {
            fn seek(offset: u32, max: usize) !u32 {
                if (offset < max or offset == Label.k_invalid_continuation) {
                    return offset;
                }
                return error.OutOfBounds;
            }

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

            fn loadFromMem(comptime T: type, memories: []const MemoryInstance, offset_from_memarg: u32, offset_from_stack: i32) !T {
                if (memories.len == 0) {
                    return error.AssertUnknownMemory;
                }

                if (offset_from_stack < 0) {
                    return error.TrapOutOfBoundsMemoryAccess;
                }

                const memory: *const MemoryInstance = &memories[0];
                const offset: usize = offset_from_memarg + @intCast(usize, offset_from_stack);

                // std.debug.print("memory.mem.len: {}, ptr: {*},. offset: {}\n", .{ memory.mem.len, memory.mem.ptr, offset });

                const bit_count = std.meta.bitCount(T);
                const read_type = switch (bit_count) {
                    8 => u8,
                    16 => u16,
                    32 => u32,
                    64 => u64,
                    else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
                };

                const end = offset + (bit_count / 8);

                // std.debug.print("memory.mem.len: {}, offset: {}, bit_count: {}, T: {}\n", .{ memory.mem.len, offset, bit_count, T });

                if (memory.mem.len < end) {
                    return error.TrapOutOfBoundsMemoryAccess;
                }

                const mem = memory.mem[offset..end];
                const value = std.mem.readIntSliceLittle(read_type, mem);
                return @bitCast(T, value);
            }

            fn storeInMem(value: anytype, memories: []const MemoryInstance, offset_from_memarg: u32, offset_from_stack: i32) !void {
                if (memories.len == 0) {
                    return error.AssertUnknownMemory;
                }

                if (offset_from_stack < 0) {
                    return error.TrapOutOfBoundsMemoryAccess;
                }

                const memory: *const MemoryInstance = &memories[0];
                const offset: u32 = offset_from_memarg + @intCast(u32, offset_from_stack);

                const bit_count = std.meta.bitCount(@TypeOf(value));
                const write_type = switch (bit_count) {
                    8 => u8,
                    16 => u16,
                    32 => u32,
                    64 => u64,
                    else => @compileError("Only types with bit counts of 8, 16, 32, or 64 are supported."),
                };

                const end = offset + (bit_count / 8);
                if (memory.mem.len < end) {
                    return error.TrapOutOfBoundsMemoryAccess;
                }

                const write_value = @bitCast(write_type, value);

                const mem = memory.mem[offset..end];
                std.mem.writeIntSliceLittle(write_type, mem, write_value);
            }
        };

        var instruction_offset: u32 = root_offset;

        // TODO use a linear allocator for scratch allocations that gets reset on each loop iteration

        while (instruction_offset < instructions.len) {
            var instruction = instructions[instruction_offset];
            var next_instruction = instruction_offset + 1;

            // std.debug.print("\tfound opcode: {} (pos {})\n", .{ instruction.opcode, instruction_offset });

            switch (instruction.opcode) {
                Opcode.Unreachable => {
                    return error.TrapUnreachable;
                },
                Opcode.Noop => {
                    unreachable;
                }, // should have been stripped in the decoding phase
                Opcode.Block => {
                    try self.enterBlock(instruction, instruction_offset);
                },
                Opcode.Loop => {
                    try self.enterBlock(instruction, instruction_offset);
                },
                Opcode.If => {
                    var condition = try self.stack.popI32();
                    if (condition != 0) {
                        // std.debug.print("\t>>> entering block at {}\n", .{instruction_offset});
                        try self.enterBlock(instruction, instruction_offset);
                    } else if (self.module_def.if_to_else_offsets.get(instruction_offset)) |else_offset| {
                        // std.debug.print("\t>>> else case hit at {}\n", .{else_offset});
                        // +1 to skip the else opcode, since it's treated as an End for the If block.
                        try self.enterBlock(instruction, else_offset);
                        next_instruction = try Helpers.seek(else_offset + 1, instructions.len);
                    } else {
                        const continuation = self.module_def.label_continuations.get(instruction_offset) orelse return error.AssertInvalidLabel;
                        // std.debug.print("\t>>> skipping to next_instruction at {}\n", .{continuation + 1});
                        next_instruction = try Helpers.seek(continuation + 1, instructions.len);
                    }
                },
                Opcode.Else => {
                    // getting here means we reached the end of the if opcode chain, so skip to the true end opcode
                    const end_offset = self.module_def.label_continuations.get(instruction_offset) orelse return error.AssertInvalidLabel;
                    next_instruction = try Helpers.seek(end_offset, instructions.len);
                },
                Opcode.End => {
                    var returns = std.ArrayList(Val).init(self.allocator);
                    defer returns.deinit();

                    // id 0 means this is the end of a function, otherwise it's the end of a block
                    const label_ptr: *const Label = self.stack.topLabel();
                    if (label_ptr.isFirstInCallFrame() == false) {
                        try popValues(&returns, &self.stack, self.getReturnTypesFromBlocktype(label_ptr.blocktype));
                        _ = try self.stack.popLabel();
                        try pushValues(returns.items, &self.stack);
                    } else {
                        var frame: *const CallFrame = try self.stack.findCurrentFrame();
                        const return_types: []const ValType = self.module_def.types.items[frame.func.type_def_index].getReturns();

                        try popValues(&returns, &self.stack, return_types);
                        var label = try self.stack.popLabel();
                        try self.stack.popFrame();
                        const is_root_function = (self.stack.size() == 0);
                        try pushValues(returns.items, &self.stack);

                        // std.debug.print("returning from func call... is root: {}\n", .{is_root_function});
                        if (is_root_function) {
                            return;
                        } else {
                            next_instruction = try Helpers.seek(label.continuation, instructions.len);
                        }
                    }
                },
                Opcode.Branch => {
                    const label_id: u32 = instruction.immediate;
                    const branch_to_instruction = try self.branch(instructions, label_id);
                    next_instruction = try Helpers.seek(branch_to_instruction, instructions.len);
                },
                Opcode.Branch_If => {
                    const label_id: u32 = instruction.immediate;
                    const v = try self.stack.popI32();
                    // std.debug.print("branch_if stack value: {}, target id: {}\n", .{v, label_id});
                    if (v != 0) {
                        const branch_to_instruction = try self.branch(instructions, label_id);
                        next_instruction = try Helpers.seek(branch_to_instruction, instructions.len);
                    }
                },
                Opcode.Branch_Table => {
                    var immediates: *const BranchTableImmediates = &self.module_def.code.branch_table.items[instruction.immediate];
                    var table: []const u32 = immediates.label_ids.items;

                    const label_index = try self.stack.popI32();
                    const label_id: u32 = if (label_index >= 0 and label_index < table.len) table[@intCast(usize, label_index)] else immediates.fallback_id;
                    const branch_to_instruction = try self.branch(instructions, label_id);

                    // std.debug.print("branch_table) label_index: {}, label_ids: {any}, label_id: {}\n", .{ label_index, immediates.label_ids.items, label_id });

                    next_instruction = try Helpers.seek(branch_to_instruction, instructions.len);
                },
                Opcode.Return => {
                    const continuation: u32 = try self.returnFromFunc();
                    next_instruction = try Helpers.seek(continuation, instructions.len);
                },
                Opcode.Call => {
                    const func_index = instruction.immediate;
                    if (self.store.functions.items.len <= func_index) {
                        return error.AssertUnknownFunction;
                    }

                    const func: *const FunctionInstance = &self.store.functions.items[@intCast(usize, func_index)];
                    try self.call(func, &next_instruction);
                },
                Opcode.Call_Indirect => {
                    var immediates: *const CallIndirectImmediates = &self.module_def.code.call_indirect.items[instruction.immediate];

                    if (self.module_def.types.items.len <= immediates.type_index) {
                        return error.AssertUnknownType;
                    }
                    if (self.store.tables.items.len <= immediates.table_index) {
                        return error.AssertUnknownTable;
                    }

                    var table: *TableInstance = &self.store.tables.items[immediates.table_index];

                    const ref_index = try self.stack.popI32();
                    if (table.refs.items.len <= ref_index or ref_index < 0) {
                        return error.TrapUndefinedElement;
                    }

                    const ref: Val = table.refs.items[@intCast(usize, ref_index)];
                    if (ref.isNull()) {
                        return error.TrapUnknown;
                    }

                    const func_index = ref.FuncRef;
                    if (self.store.functions.items.len <= func_index) {
                        return error.AssertUnknownFunction;
                    }

                    const func: *const FunctionInstance = &self.store.functions.items[func_index];
                    if (func.type_def_index != immediates.type_index) {
                        return error.TrapIndirectCallTypeMismatch;
                    }

                    try self.call(func, &next_instruction);
                },
                Opcode.Drop => {
                    _ = try self.stack.popValue();
                },
                Opcode.Select => {
                    var boolean = try self.stack.popI32();
                    var v2 = try self.stack.popValue();
                    var v1 = try self.stack.popValue();

                    if (std.meta.activeTag(v1) != std.meta.activeTag(v2)) {
                        return error.AssertTypeMismatch;
                    }

                    if (boolean != 0) {
                        try self.stack.pushValue(v1);
                    } else {
                        try self.stack.pushValue(v2);
                    }
                },
                Opcode.Local_Get => {
                    var locals_index: u32 = instruction.immediate;
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    var v: Val = frame.locals.items[locals_index];
                    try self.stack.pushValue(v);
                },
                Opcode.Local_Set => {
                    var locals_index: u32 = instruction.immediate;
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    var v: Val = try self.stack.popValue();

                    frame.locals.items[locals_index] = v;
                },
                Opcode.Local_Tee => {
                    var locals_index: u32 = instruction.immediate;
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    var v: Val = try self.stack.topValue();
                    frame.locals.items[locals_index] = v;
                },
                Opcode.Global_Get => {
                    var global_index: u32 = instruction.immediate;
                    var global = &self.store.globals.items[global_index];
                    try self.stack.pushValue(global.value);
                },
                Opcode.Global_Set => {
                    var global_index: u32 = instruction.immediate;
                    var global = &self.store.globals.items[global_index];
                    if (global.mut == GlobalMut.Immutable) {
                        return error.AssertAttemptToSetImmutable;
                    }
                    global.value = try self.stack.popValue();
                },
                Opcode.I32_Load => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value = try Helpers.loadFromMem(i32, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI32(value);
                },
                Opcode.I64_Load => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value = try Helpers.loadFromMem(i64, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI64(value);
                },
                Opcode.F32_Load => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value = try Helpers.loadFromMem(f32, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushF32(value);
                },
                Opcode.F64_Load => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value = try Helpers.loadFromMem(f64, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushF64(value);
                },
                Opcode.I32_Load8_S => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: i32 = try Helpers.loadFromMem(i8, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Load8_U => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: u32 = try Helpers.loadFromMem(u8, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI32(@bitCast(i32, value));
                },
                Opcode.I32_Load16_S => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: i32 = try Helpers.loadFromMem(i16, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Load16_U => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: u32 = try Helpers.loadFromMem(u16, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI32(@bitCast(i32, value));
                },
                Opcode.I64_Load8_S => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: i64 = try Helpers.loadFromMem(i8, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Load8_U => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: u64 = try Helpers.loadFromMem(u8, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI64(@bitCast(i64, value));
                },
                Opcode.I64_Load16_S => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: i64 = try Helpers.loadFromMem(i16, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Load16_U => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: u64 = try Helpers.loadFromMem(u16, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI64(@bitCast(i64, value));
                },
                Opcode.I64_Load32_S => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: i64 = try Helpers.loadFromMem(i32, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Load32_U => {
                    var offset_from_stack: i32 = try self.stack.popI32();
                    var value: u64 = try Helpers.loadFromMem(u32, self.store.memories.items, instruction.immediate, offset_from_stack);
                    try self.stack.pushI64(@bitCast(i64, value));
                },
                Opcode.I32_Store => {
                    const value: i32 = try self.stack.popI32();
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.I64_Store => {
                    const value: i64 = try self.stack.popI64();
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.F32_Store => {
                    const value: f32 = try self.stack.popF32();
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.F64_Store => {
                    const value: f64 = try self.stack.popF64();
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.I32_Store8 => {
                    const value: i8 = @truncate(i8, try self.stack.popI32());
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.I32_Store16 => {
                    const value: i16 = @truncate(i16, try self.stack.popI32());
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.I64_Store8 => {
                    const value: i8 = @truncate(i8, try self.stack.popI64());
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.I64_Store16 => {
                    const value: i16 = @truncate(i16, try self.stack.popI64());
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.I64_Store32 => {
                    const value: i32 = @truncate(i32, try self.stack.popI64());
                    const offset_from_stack: i32 = try self.stack.popI32();
                    try Helpers.storeInMem(value, self.store.memories.items, instruction.immediate, offset_from_stack);
                },
                Opcode.Memory_Size => {
                    const memory_index: usize = 0;

                    if (self.store.memories.items.len <= memory_index) {
                        return error.AssertMemoryInvalidIndex;
                    }

                    const num_pages: i32 = @intCast(i32, self.store.memories.items[memory_index].limits.min);

                    try self.stack.pushI32(num_pages);
                },
                Opcode.Memory_Grow => {
                    const memory_index: usize = 0;

                    if (self.store.memories.items.len <= memory_index) {
                        return error.AssertMemoryInvalidIndex;
                    }

                    var memory_instance: *MemoryInstance = &self.store.memories.items[memory_index];

                    const old_num_pages: i32 = @intCast(i32, memory_instance.limits.min);
                    const num_pages: i32 = try self.stack.popI32();

                    if (num_pages >= 0 and memory_instance.grow(@intCast(usize, num_pages))) {
                        try self.stack.pushI32(old_num_pages);
                    } else {
                        try self.stack.pushI32(-1);
                    }
                },
                Opcode.I32_Const => {
                    var v: i32 = @bitCast(i32, instruction.immediate);
                    try self.stack.pushI32(v);
                },
                Opcode.I64_Const => {
                    var v: i64 = self.module_def.code.i64_const.items[instruction.immediate];
                    try self.stack.pushI64(v);
                },
                Opcode.F32_Const => {
                    var v: f32 = @bitCast(f32, instruction.immediate);
                    try self.stack.pushF32(v);
                },
                Opcode.F64_Const => {
                    var v: f64 = self.module_def.code.f64_const.items[instruction.immediate];
                    try self.stack.pushF64(v);
                },
                Opcode.I32_Eqz => {
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 == 0) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_Eq => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 == v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_NE => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 != v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_LT_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_LT_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_GT_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_GT_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_LE_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_LE_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_GE_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_GE_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_Eqz => {
                    var v1: i64 = try self.stack.popI64();
                    var result: i32 = if (v1 == 0) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_Eq => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result: i32 = if (v1 == v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_NE => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result: i32 = if (v1 != v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_LT_S => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_LT_U => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_GT_S => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_GT_U => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_LE_S => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_LE_U => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_GE_S => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.I64_GE_U => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Opcode.F32_EQ => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value: i32 = if (v1 == v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F32_NE => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value: i32 = if (v1 != v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F32_LT => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F32_GT => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F32_LE => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F32_GE => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F64_EQ => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value: i32 = if (v1 == v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F64_NE => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value: i32 = if (v1 != v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F64_LT => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F64_GT => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F64_LE => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.F64_GE => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Clz => {
                    var v: i32 = try self.stack.popI32();
                    var num_zeroes = @clz(i32, v);
                    try self.stack.pushI32(num_zeroes);
                },
                Opcode.I32_Ctz => {
                    var v: i32 = try self.stack.popI32();
                    var num_zeroes = @ctz(i32, v);
                    try self.stack.pushI32(num_zeroes);
                },
                Opcode.I32_Popcnt => {
                    var v: i32 = try self.stack.popI32();
                    var num_bits_set = @popCount(i32, v);
                    try self.stack.pushI32(num_bits_set);
                },
                Opcode.I32_Add => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result = v1 +% v2;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_Sub => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result = v1 -% v2;
                    try self.stack.pushI32(result);
                },
                Opcode.I32_Mul => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var value = v1 *% v2;
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Div_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var value = std.math.divTrunc(i32, v1, v2) catch |e| {
                        if (e == error.DivisionByZero) {
                            return error.TrapIntegerDivisionByZero;
                        } else if (e == error.Overflow) {
                            return error.TrapIntegerOverflow;
                        } else {
                            return e;
                        }
                    };
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Div_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
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
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Rem_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var denom = try std.math.absInt(v2);
                    var value = std.math.rem(i32, v1, denom) catch |e| {
                        if (e == error.DivisionByZero) {
                            return error.TrapIntegerDivisionByZero;
                        } else {
                            return e;
                        }
                    };
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Rem_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value_unsigned = std.math.rem(u32, v1, v2) catch |e| {
                        if (e == error.DivisionByZero) {
                            return error.TrapIntegerDivisionByZero;
                        } else {
                            return e;
                        }
                    };
                    var value = @bitCast(i32, value_unsigned);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_And => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 & v2);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Or => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 | v2);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Xor => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 ^ v2);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Shl => {
                    var shift_unsafe: i32 = try self.stack.popI32();
                    var int: i32 = try self.stack.popI32();
                    var shift: i32 = try std.math.mod(i32, shift_unsafe, 32);
                    var value = std.math.shl(i32, int, shift);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Shr_S => {
                    var shift_unsafe: i32 = try self.stack.popI32();
                    var int: i32 = try self.stack.popI32();
                    var shift = try std.math.mod(i32, shift_unsafe, 32);
                    var value = std.math.shr(i32, int, shift);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Shr_U => {
                    var shift_unsafe: u32 = @bitCast(u32, try self.stack.popI32());
                    var int: u32 = @bitCast(u32, try self.stack.popI32());
                    var shift = try std.math.mod(u32, shift_unsafe, 32);
                    var value = @bitCast(i32, std.math.shr(u32, int, shift));
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Rotl => {
                    var rot: u32 = @bitCast(u32, try self.stack.popI32());
                    var int: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, std.math.rotl(u32, int, rot));
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Rotr => {
                    var rot: u32 = @bitCast(u32, try self.stack.popI32());
                    var int: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, std.math.rotr(u32, int, rot));
                    try self.stack.pushI32(value);
                },
                Opcode.I64_Clz => {
                    var v: i64 = try self.stack.popI64();
                    var num_zeroes = @clz(i64, v);
                    try self.stack.pushI64(num_zeroes);
                },
                Opcode.I64_Ctz => {
                    var v: i64 = try self.stack.popI64();
                    var num_zeroes = @ctz(i64, v);
                    try self.stack.pushI64(num_zeroes);
                },
                Opcode.I64_Popcnt => {
                    var v: i64 = try self.stack.popI64();
                    var num_bits_set = @popCount(i64, v);
                    try self.stack.pushI64(num_bits_set);
                },
                Opcode.I64_Add => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result = v1 +% v2;
                    try self.stack.pushI64(result);
                },
                Opcode.I64_Sub => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var result = v1 -% v2;
                    try self.stack.pushI64(result);
                },
                Opcode.I64_Mul => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var value = v1 *% v2;
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Div_S => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var value = std.math.divTrunc(i64, v1, v2) catch |e| {
                        if (e == error.DivisionByZero) {
                            return error.TrapIntegerDivisionByZero;
                        } else if (e == error.Overflow) {
                            return error.TrapIntegerOverflow;
                        } else {
                            return e;
                        }
                    };
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Div_U => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
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
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Rem_S => {
                    var v2: i64 = try self.stack.popI64();
                    var v1: i64 = try self.stack.popI64();
                    var denom = try std.math.absInt(v2);
                    var value = std.math.rem(i64, v1, denom) catch |e| {
                        if (e == error.DivisionByZero) {
                            return error.TrapIntegerDivisionByZero;
                        } else {
                            return e;
                        }
                    };
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Rem_U => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var value_unsigned = std.math.rem(u64, v1, v2) catch |e| {
                        if (e == error.DivisionByZero) {
                            return error.TrapIntegerDivisionByZero;
                        } else {
                            return e;
                        }
                    };
                    var value = @bitCast(i64, value_unsigned);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_And => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var value = @bitCast(i64, v1 & v2);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Or => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var value = @bitCast(i64, v1 | v2);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Xor => {
                    var v2: u64 = @bitCast(u64, try self.stack.popI64());
                    var v1: u64 = @bitCast(u64, try self.stack.popI64());
                    var value = @bitCast(i64, v1 ^ v2);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Shl => {
                    var shift_unsafe: i64 = try self.stack.popI64();
                    var int: i64 = try self.stack.popI64();
                    var shift: i64 = try std.math.mod(i64, shift_unsafe, 64);
                    var value = std.math.shl(i64, int, shift);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Shr_S => {
                    var shift_unsafe: i64 = try self.stack.popI64();
                    var int: i64 = try self.stack.popI64();
                    var shift = try std.math.mod(i64, shift_unsafe, 64);
                    var value = std.math.shr(i64, int, shift);
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Shr_U => {
                    var shift_unsafe: u64 = @bitCast(u64, try self.stack.popI64());
                    var int: u64 = @bitCast(u64, try self.stack.popI64());
                    var shift = try std.math.mod(u64, shift_unsafe, 64);
                    var value = @bitCast(i64, std.math.shr(u64, int, shift));
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Rotl => {
                    var rot: u64 = @bitCast(u64, try self.stack.popI64());
                    var int: u64 = @bitCast(u64, try self.stack.popI64());
                    var value = @bitCast(i64, std.math.rotl(u64, int, rot));
                    try self.stack.pushI64(value);
                },
                Opcode.I64_Rotr => {
                    var rot: u64 = @bitCast(u64, try self.stack.popI64());
                    var int: u64 = @bitCast(u64, try self.stack.popI64());
                    var value = @bitCast(i64, std.math.rotr(u64, int, rot));
                    try self.stack.pushI64(value);
                },
                Opcode.F32_Abs => {
                    var f = try self.stack.popF32();
                    var value = std.math.fabs(f);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Neg => {
                    var f = try self.stack.popF32();
                    try self.stack.pushF32(-f);
                },
                Opcode.F32_Ceil => {
                    var f = try self.stack.popF32();
                    var value = @ceil(f);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Floor => {
                    var f = try self.stack.popF32();
                    var value = @floor(f);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Trunc => {
                    var f = try self.stack.popF32();
                    var value = @trunc(f);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Nearest => {
                    var f = try self.stack.popF32();
                    var value: f32 = @trunc(f);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Sqrt => {
                    var f = try self.stack.popF32();
                    var value = std.math.sqrt(f);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Add => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value = v1 + v2;
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Sub => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value = v1 - v2;
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Mul => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value = v1 * v2;
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Div => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value = v1 / v2;
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Min => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value = Helpers.propagateNanWithOp(std.math.min, v1, v2);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Max => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value = Helpers.propagateNanWithOp(std.math.max, v1, v2);
                    try self.stack.pushF32(value);
                },
                Opcode.F32_Copysign => {
                    var v2 = try self.stack.popF32();
                    var v1 = try self.stack.popF32();
                    var value = std.math.copysign(f32, v1, v2);
                    try self.stack.pushF32(value);
                },
                Opcode.F64_Abs => {
                    var f = try self.stack.popF64();
                    var value = std.math.fabs(f);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Neg => {
                    var f = try self.stack.popF64();
                    try self.stack.pushF64(-f);
                },
                Opcode.F64_Ceil => {
                    var f = try self.stack.popF64();
                    var value = @ceil(f);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Floor => {
                    var f = try self.stack.popF64();
                    var value = @floor(f);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Trunc => {
                    var f = try self.stack.popF64();
                    var value = @trunc(f);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Nearest => {
                    var f = try self.stack.popF64();
                    var value: f64 = @trunc(f);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Sqrt => {
                    var f = try self.stack.popF64();
                    var value = std.math.sqrt(f);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Add => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value = v1 + v2;
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Sub => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value = v1 - v2;
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Mul => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value = v1 * v2;
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Div => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value = v1 / v2;
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Min => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value = Helpers.propagateNanWithOp(std.math.min, v1, v2);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Max => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value = Helpers.propagateNanWithOp(std.math.max, v1, v2);
                    try self.stack.pushF64(value);
                },
                Opcode.F64_Copysign => {
                    var v2 = try self.stack.popF64();
                    var v1 = try self.stack.popF64();
                    var value = std.math.copysign(f64, v1, v2);
                    try self.stack.pushF64(value);
                },
                Opcode.I32_Wrap_I64 => {
                    var v = try self.stack.popI64();
                    var mod = @truncate(i32, v);
                    try self.stack.pushI32(mod);
                },
                Opcode.I32_Trunc_F32_S => {
                    var v = try self.stack.popF32();
                    var int = try Helpers.truncateTo(i32, v);
                    try self.stack.pushI32(int);
                },
                Opcode.I32_Trunc_F32_U => {
                    var v = try self.stack.popF32();
                    var int = try Helpers.truncateTo(u32, v);
                    try self.stack.pushI32(@bitCast(i32, int));
                },
                Opcode.I32_Trunc_F64_S => {
                    var v = try self.stack.popF64();
                    var int = try Helpers.truncateTo(i32, v);
                    try self.stack.pushI32(int);
                },
                Opcode.I32_Trunc_F64_U => {
                    var v = try self.stack.popF64();
                    var int = try Helpers.truncateTo(u32, v);
                    try self.stack.pushI32(@bitCast(i32, int));
                },
                Opcode.I64_Extend_I32_S => {
                    var v32 = try self.stack.popI32();
                    var v64: i64 = v32;
                    try self.stack.pushI64(v64);
                },
                Opcode.I64_Extend_I32_U => {
                    var v32 = try self.stack.popI32();
                    var v64: u64 = @bitCast(u32, v32);
                    try self.stack.pushI64(@bitCast(i64, v64));
                },
                Opcode.I64_Trunc_F32_S => {
                    var v = try self.stack.popF32();
                    var int = try Helpers.truncateTo(i64, v);
                    try self.stack.pushI64(int);
                },
                Opcode.I64_Trunc_F32_U => {
                    var v = try self.stack.popF32();
                    var int = try Helpers.truncateTo(u64, v);
                    try self.stack.pushI64(@bitCast(i64, int));
                },
                Opcode.I64_Trunc_F64_S => {
                    var v = try self.stack.popF64();
                    var int = try Helpers.truncateTo(i64, v);
                    try self.stack.pushI64(int);
                },
                Opcode.I64_Trunc_F64_U => {
                    var v = try self.stack.popF64();
                    var int = try Helpers.truncateTo(u64, v);
                    try self.stack.pushI64(@bitCast(i64, int));
                },
                Opcode.F32_Convert_I32_S => {
                    var v = try self.stack.popI32();
                    try self.stack.pushF32(@intToFloat(f32, v));
                },
                Opcode.F32_Convert_I32_U => {
                    var v = @bitCast(u32, try self.stack.popI32());
                    try self.stack.pushF32(@intToFloat(f32, v));
                },
                Opcode.F32_Convert_I64_S => {
                    var v = try self.stack.popI64();
                    try self.stack.pushF32(@intToFloat(f32, v));
                },
                Opcode.F32_Convert_I64_U => {
                    var v = @bitCast(u64, try self.stack.popI64());
                    try self.stack.pushF32(@intToFloat(f32, v));
                },
                Opcode.F32_Demote_F64 => {
                    var v = try self.stack.popF64();
                    try self.stack.pushF32(@floatCast(f32, v));
                },
                Opcode.F64_Convert_I32_S => {
                    var v = try self.stack.popI32();
                    try self.stack.pushF64(@intToFloat(f64, v));
                },
                Opcode.F64_Convert_I32_U => {
                    var v = @bitCast(u32, try self.stack.popI32());
                    try self.stack.pushF64(@intToFloat(f64, v));
                },
                Opcode.F64_Convert_I64_S => {
                    var v = try self.stack.popI64();
                    try self.stack.pushF64(@intToFloat(f64, v));
                },
                Opcode.F64_Convert_I64_U => {
                    var v = @bitCast(u64, try self.stack.popI64());
                    try self.stack.pushF64(@intToFloat(f64, v));
                },
                Opcode.F64_Promote_F32 => {
                    var v = try self.stack.popF32();
                    try self.stack.pushF64(@floatCast(f64, v));
                },
                Opcode.I32_Reinterpret_F32 => {
                    var v = try self.stack.popF32();
                    try self.stack.pushI32(@bitCast(i32, v));
                },
                Opcode.I64_Reinterpret_F64 => {
                    var v = try self.stack.popF64();
                    try self.stack.pushI64(@bitCast(i64, v));
                },
                Opcode.F32_Reinterpret_I32 => {
                    var v = try self.stack.popI32();
                    try self.stack.pushF32(@bitCast(f32, v));
                },
                Opcode.F64_Reinterpret_I64 => {
                    var v = try self.stack.popI64();
                    try self.stack.pushF64(@bitCast(f64, v));
                },
                Opcode.I32_Extend8_S => {
                    var v = try self.stack.popI32();
                    var v_truncated = @truncate(i8, v);
                    var v_extended: i32 = v_truncated;
                    try self.stack.pushI32(v_extended);
                },
                Opcode.I32_Extend16_S => {
                    var v = try self.stack.popI32();
                    var v_truncated = @truncate(i16, v);
                    var v_extended: i32 = v_truncated;
                    try self.stack.pushI32(v_extended);
                },
                Opcode.I64_Extend8_S => {
                    var v = try self.stack.popI64();
                    var v_truncated = @truncate(i8, v);
                    var v_extended: i64 = v_truncated;
                    try self.stack.pushI64(v_extended);
                },
                Opcode.I64_Extend16_S => {
                    var v = try self.stack.popI64();
                    var v_truncated = @truncate(i16, v);
                    var v_extended: i64 = v_truncated;
                    try self.stack.pushI64(v_extended);
                },
                Opcode.I64_Extend32_S => {
                    var v = try self.stack.popI64();
                    var v_truncated = @truncate(i32, v);
                    var v_extended: i64 = v_truncated;
                    try self.stack.pushI64(v_extended);
                },
                Opcode.Ref_Null => {
                    var valtype = @intToEnum(ValType, instruction.immediate);
                    var val = try Val.nullRef(valtype);
                    try self.stack.pushValue(val);
                },
                Opcode.Ref_Is_Null => {
                    const val: Val = try self.stack.popValue();
                    if (val.isRefType() == false) {
                        return error.AssertTypeMismatch;
                    }
                    const boolean: i32 = if (val.isNull()) 1 else 0;
                    try self.stack.pushI32(boolean);
                },
                Opcode.Ref_Func => {
                    const func_index = instruction.immediate;
                    const val = Val{ .FuncRef = func_index };
                    try self.stack.pushValue(val);
                },
                Opcode.I32_Trunc_Sat_F32_S => {
                    var v = try self.stack.popF32();
                    var int = Helpers.saturatedTruncateTo(i32, v);
                    try self.stack.pushI32(int);
                },
                Opcode.I32_Trunc_Sat_F32_U => {
                    var v = try self.stack.popF32();
                    var int = Helpers.saturatedTruncateTo(u32, v);
                    try self.stack.pushI32(@bitCast(i32, int));
                },
                Opcode.I32_Trunc_Sat_F64_S => {
                    var v = try self.stack.popF64();
                    var int = Helpers.saturatedTruncateTo(i32, v);
                    try self.stack.pushI32(int);
                },
                Opcode.I32_Trunc_Sat_F64_U => {
                    var v = try self.stack.popF64();
                    var int = Helpers.saturatedTruncateTo(u32, v);
                    try self.stack.pushI32(@bitCast(i32, int));
                },
                Opcode.I64_Trunc_Sat_F32_S => {
                    var v = try self.stack.popF32();
                    var int = Helpers.saturatedTruncateTo(i64, v);
                    try self.stack.pushI64(int);
                },
                Opcode.I64_Trunc_Sat_F32_U => {
                    var v = try self.stack.popF32();
                    var int = Helpers.saturatedTruncateTo(u64, v);
                    try self.stack.pushI64(@bitCast(i64, int));
                },
                Opcode.I64_Trunc_Sat_F64_S => {
                    var v = try self.stack.popF64();
                    var int = Helpers.saturatedTruncateTo(i64, v);
                    try self.stack.pushI64(int);
                },
                Opcode.I64_Trunc_Sat_F64_U => {
                    var v = try self.stack.popF64();
                    var int = Helpers.saturatedTruncateTo(u64, v);
                    try self.stack.pushI64(@bitCast(i64, int));
                },
                Opcode.Memory_Init => {
                    const data_index: u32 = instruction.immediate;
                    const data: *const DataDefinition = &self.module_def.datas.items[data_index];
                    const memory: *MemoryInstance = &self.store.memories.items[0];

                    const length = try self.stack.popI32();
                    const data_offset = try self.stack.popI32();
                    const memory_offset = try self.stack.popI32();

                    if (length < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }
                    if (data.bytes.items.len < data_offset + length or data_offset < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }
                    if (memory.mem.len < memory_offset + length or memory_offset < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }

                    const data_offset_u32 = @intCast(u32, data_offset);
                    const memory_offset_u32 = @intCast(u32, memory_offset);
                    const length_u32 = @intCast(u32, length);

                    var source = data.bytes.items[data_offset_u32 .. data_offset_u32 + length_u32];
                    var destination = memory.mem[memory_offset_u32 .. memory_offset_u32 + length_u32];
                    std.mem.copy(u8, destination, source);
                },
                Opcode.Data_Drop => {
                    const data_index: u32 = instruction.immediate;
                    var data: *DataDefinition = &self.module_def.datas.items[data_index];
                    data.bytes.clearAndFree();
                },
                Opcode.Memory_Copy => {
                    const memory: *MemoryInstance = &self.store.memories.items[0];

                    const length = try self.stack.popI32();
                    const source_offset = try self.stack.popI32();
                    const dest_offset = try self.stack.popI32();

                    if (length < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }
                    if (memory.mem.len < source_offset + length or source_offset < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }
                    if (memory.mem.len < dest_offset + length or dest_offset < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }

                    const source_offset_u32 = @intCast(u32, source_offset);
                    const dest_offset_u32 = @intCast(u32, dest_offset);
                    const length_u32 = @intCast(u32, length);

                    var source = memory.mem[source_offset_u32 .. source_offset_u32 + length_u32];
                    var destination = memory.mem[dest_offset_u32 .. dest_offset_u32 + length_u32];

                    if (@ptrToInt(destination.ptr) < @ptrToInt(source.ptr)) {
                        std.mem.copy(u8, destination, source);
                    } else {
                        std.mem.copyBackwards(u8, destination, source);
                    }
                },
                Opcode.Memory_Fill => {
                    const memory: *MemoryInstance = &self.store.memories.items[0];

                    const length = try self.stack.popI32();
                    const value: u8 = @truncate(u8, @bitCast(u32, try self.stack.popI32()));
                    const offset = try self.stack.popI32();

                    if (length < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }
                    if (memory.mem.len < offset + length or offset < 0) {
                        return error.TrapOutOfBoundsMemoryAccess;
                    }

                    const offset_u32 = @intCast(u32, offset);
                    const length_u32 = @intCast(u32, length);

                    var destination = memory.mem[offset_u32 .. offset_u32 + length_u32];

                    std.mem.set(u8, destination, value);
                },
            }

            instruction_offset = next_instruction;
        }
    }

    fn call(self: *ModuleInstance, func: *const FunctionInstance, instruction_offset: *u32) !void {
        const functype: *const FunctionTypeDefinition = &self.module_def.types.items[func.type_def_index];

        var frame = CallFrame{
            .func = func,
            .locals = std.ArrayList(Val).init(self.allocator),
        };

        const param_types: []const ValType = functype.getParams();

        try frame.locals.resize(func.local_types.items.len);

        var param_index = param_types.len;
        while (param_index > 0) {
            param_index -= 1;
            var value = try self.stack.popValue();
            if (std.meta.activeTag(value) != param_types[param_index]) {
                std.debug.print("\tExpected value of type {}, but got {}\n", .{ param_types[param_index], value });
                return error.AssertTypeMismatch;
            }
            frame.locals.items[param_index] = value;
        }

        var locals_index: usize = param_types.len;
        while (locals_index < func.local_types.items.len) : (locals_index += 1) {
            frame.locals.items[locals_index] = Val.default(func.local_types.items[locals_index]);
        }

        const continuation: u32 = instruction_offset.*;

        try self.stack.pushFrame(frame);
        try self.stack.pushLabel(BlockTypeValue{ .TypeIndex = func.type_def_index }, continuation);

        instruction_offset.* = func.offset_into_instructions;
    }

    fn enterBlock(self: *ModuleInstance, instruction: Instruction, label_offset: u32) !void {
        var block_type_value = self.module_def.code.block_type_values.items[instruction.immediate];

        var params = std.ArrayList(Val).init(self.allocator);
        defer params.deinit();

        switch (block_type_value) {
            .TypeIndex => {
                const type_index = block_type_value.TypeIndex;
                const func_type: *const FunctionTypeDefinition = &self.module_def.types.items[type_index];
                const type_params: []const ValType = func_type.getParams();

                try popValues(&params, &self.stack, type_params);
            },
            else => {},
        }

        const continuation = self.module_def.label_continuations.get(label_offset) orelse return error.AssertInvalidLabel;
        try self.stack.pushLabel(block_type_value, continuation);

        try pushValues(params.items, &self.stack);
    }

    fn branch(self: *ModuleInstance, instructions: []const Instruction, label_id: u32) !u32 {
        // std.debug.print("\tbranching to label {}\n", .{label_id});
        const label: *const Label = try self.stack.findLabel(label_id);
        if (label.isFirstInCallFrame()) {
            return try self.returnFromFunc();
        }
        const continuation = label.continuation;

        // std.debug.print("found label: {}\n", .{label});

        const is_loop_continuation = instructions[continuation].opcode == .Loop;

        if (is_loop_continuation == false or label_id != 0) {
            var args = std.ArrayList(Val).init(self.allocator);
            defer args.deinit();

            const return_types: []const ValType = self.getReturnTypesFromBlocktype(label.blocktype);
            // std.debug.print("looking for return types: {any}", .{return_types});
            try popValues(&args, &self.stack, return_types);

            var stack_label_id: u32 = 0;
            while (true) {
                var topItem = try self.stack.top();
                switch (topItem.*) {
                    .Val => {
                        _ = try self.stack.popValue();
                    },
                    .Frame => {
                        return error.AssertInvalidLabel;
                    },
                    .Label => {
                        if (stack_label_id == label_id) {
                            if (is_loop_continuation == false) {
                                _ = try self.stack.popLabel();
                            }
                            break;
                        } else {
                            _ = try self.stack.popLabel();
                            stack_label_id += 1;
                        }
                    },
                }
            }

            try pushValues(args.items, &self.stack);
        }

        // std.debug.print("\tbranching to continuation: {}, stack state:\n\t{any}\n", .{ continuation, self.stack.stack.items });
        return continuation + 1; // branching takes care of popping/pushing values so skip the End instruction
    }

    fn returnFromFunc(self: *ModuleInstance) !u32 {
        var frame: *const CallFrame = try self.stack.findCurrentFrame();
        const return_types: []const ValType = self.module_def.types.items[frame.func.type_def_index].getReturns();

        var returns = std.ArrayList(Val).init(self.allocator);
        defer returns.deinit();
        try returns.ensureTotalCapacity(return_types.len);

        // std.debug.print("stack: {any}, expected: {any}\n", .{ self.stack.stack.items, return_types });

        while (returns.items.len < return_types.len) {
            var value = try self.stack.popValue();
            if (std.meta.activeTag(value) != return_types[return_types.len - returns.items.len - 1]) {
                std.debug.print("\tExpected value of type {}, but got {}\n", .{ return_types[returns.items.len], value });
                return error.AssertTypeMismatch;
            }
            try returns.append(value);
        }

        var last_label: Label = undefined;
        while (true) {
            var item: *const StackItem = try self.stack.top();
            switch (item.*) {
                .Val => {
                    _ = try self.stack.popValue();
                },
                .Label => {
                    last_label = try self.stack.popLabel();
                },
                .Frame => {
                    _ = try self.stack.popFrame();
                    break;
                },
            }
        }

        const is_root_function = (self.stack.size() == 0);

        // std.debug.print("is_root_function: {}\n", .{is_root_function});
        // std.debug.print("stack: {s}\n", .{self.stack.stack.items});

        // std.debug.print("pushing returns: {s}\n", .{returns});
        while (returns.items.len > 0) {
            var value = returns.orderedRemove(returns.items.len - 1);
            try self.stack.pushValue(value);
        }

        // std.debug.print("returning from func call... is root: {}\n", .{is_root_function});
        if (is_root_function) {
            return Label.k_invalid_continuation;
        } else {
            return last_label.continuation;
        }
    }

    fn getReturnTypesFromBlocktype(self: *ModuleInstance, blocktype: BlockTypeValue) []const ValType {
        const Statics = struct {
            const empty = [_]ValType{};
            const valtype_i32 = [_]ValType{.I32};
            const valtype_i64 = [_]ValType{.I64};
            const valtype_f32 = [_]ValType{.F32};
            const valtype_f64 = [_]ValType{.F64};
            const reftype_funcref = [_]ValType{.FuncRef};
            const reftype_externref = [_]ValType{.ExternRef};
        };

        switch (blocktype) {
            .Void => return &Statics.empty,
            .ValType => |v| return switch (v) {
                .I32 => &Statics.valtype_i32,
                .I64 => &Statics.valtype_i64,
                .F32 => &Statics.valtype_f32,
                .F64 => &Statics.valtype_f64,
                .FuncRef => &Statics.reftype_funcref,
                .ExternRef => &Statics.reftype_externref,
            },
            .TypeIndex => |index| return self.module_def.types.items[index].getReturns(),
        }
    }

    fn popValues(returns: *std.ArrayList(Val), stack: *Stack, types: []const ValType) !void {
        // std.debug.print("popValues: required: {any} ({})\n", .{types, types.len});

        try returns.ensureTotalCapacity(types.len);
        while (returns.items.len < types.len) {
            // std.debug.print("returns.items.len < types.len: {}, {}\n", .{returns.items.len, types.len});
            var item = try stack.popValue();
            if (types[types.len - returns.items.len - 1] != std.meta.activeTag(item)) {
                std.debug.print("popValues mismatch: required: {s}, got {}\n", .{ types, item });
                return error.AssertTypeMismatch;
            }
            try returns.append(item);
        }
    }

    fn pushValues(returns: []const Val, stack: *Stack) !void {
        var index = returns.len;
        while (index > 0) {
            index -= 1;
            var item = returns[index];
            try stack.pushValue(item);
        }
    }
};
