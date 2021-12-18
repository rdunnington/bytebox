const std = @import("std");
const builtin = @import("builtin");

const ModuleDecodeError = error{
    UnsupportedWasmVersion,
    InvalidMagicSignature,
    InvalidValType,
    InvalidBytecode,
    InvalidExport,
    InvalidGlobalInit,
    InvalidLabel,
    InvalidConstantExpression,
    InvalidElement,
    OneTableAllowed,
    TableMaxExceeded,
    OneMemoryAllowed,
    MemoryMaxPagesExceeded,
    MemoryInvalidMaxLimit,
};

const InterpreterError = error{
    Unreachable,
    IncompleteInstruction,
    UnknownInstruction,
    TypeMismatch,
    UnknownExport,
    AttemptToSetImmutable,
    MissingLabel,
    MissingCallFrame,
    LabelMismatch,
    InvalidFunction,
    MemoryMaxReached,
    MemoryInvalidIndex,
};

const Opcode = enum(u8) {
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
    I32_Load8_S = 0x2C,
    I32_Load8_U = 0x2D,
    I32_Load16_S = 0x2E,
    I32_Load16_U = 0x2F,
    I32_Store = 0x36,
    I32_Store8 = 0x3A,
    I32_Store16 = 0x3B,
    Memory_Size = 0x3F,
    Memory_Grow = 0x40,
    I32_Const = 0x41,
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

    I32_Extend8_S = 0xC0,
    I32_Extend16_S = 0xC1,

    // fn hasImmediates(opcode:Opcode) bool {
    //     const v = switch (opcode) {
    //         .Local_Get => true,
    //         .Local_Set => true,
    //         .Local_Tee => true,
    //         .Global_Get => true,
    //         .Global_Set => true,
    //         .I32_Const => true,
    //         .Block => true,
    //         .Loop => true,
    //         .Branch => true,
    //         .Branch_If => true,
    //         .Branch_Table => true,
    //         .If => true,
    //         else => false,
    //     };
    //     return v;
    // }

    fn expectsEnd(opcode: Opcode) bool {
        return switch (opcode) {
            .Block => true,
            .Loop => true,
            .If => true,
            else => false,
        };
    }
};

const BytecodeBufferStream = std.io.FixedBufferStream([]const u8);

const ValType = enum(u8) {
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
                return ModuleDecodeError.InvalidValType;
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
    ExternRef: void, // TODO
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
    id: u32,
    blocktype: BlockTypeValue,
    continuation: u32,
    last_label_index: i32,
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
            .Label => return error.TypeMismatch,
            .Frame => return error.TypeMismatch,
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
        switch (item) {
            .Val => |v| return v,
            .Label => return error.TypeMismatch,
            .Frame => return error.TypeMismatch,
        }
    }

    fn pushLabel(self: *Self, blocktype: BlockTypeValue, continuation: u32) !void {
        // std.debug.print(">> push label: {}\n", .{self.next_label_id});
        const id: u32 = self.next_label_id;
        var item = StackItem{ .Label = .{
            .id = id,
            .blocktype = blocktype,
            .continuation = continuation,
            .last_label_index = self.last_label_index,
        } };
        try self.stack.append(item);

        self.last_label_index = @intCast(i32, self.stack.items.len) - 1;
        self.next_label_id += 1;
    }

    fn popLabel(self: *Self) !Label {
        // std.debug.print(">> pop label: {}\n", .{self.next_label_id});
        var item = try self.pop();
        var label = switch (item) {
            .Val => return error.TypeMismatch,
            .Label => |label| label,
            .Frame => return error.TypeMismatch,
        };

        self.last_label_index = label.last_label_index;
        self.next_label_id = label.id;

        return label;
    }

    fn topLabel(self: *const Self) *const Label {
        return &self.stack.items[@intCast(usize, self.last_label_index)].Label;
    }

    fn findLabel(self: *Self, id: u32) !*const Label {
        if (self.last_label_index < 0) {
            return error.InvalidLabel;
        }

        var label_index = self.last_label_index;
        while (label_index > 0) {
            switch (self.stack.items[@intCast(usize, label_index)]) {
                .Label => |*label| {
                    const label_id_from_top = (self.next_label_id - 1) - label.id;
                    // std.debug.print("found label_id_from_top: {}\n", .{label_id_from_top});
                    if (label_id_from_top == id) {
                        return label;
                    } else {
                        label_index = label.last_label_index;
                        if (label_index == -1) {
                            return error.InvalidLabel;
                        }
                    }
                },
                else => {
                    unreachable; // last_label_index should only point to Labels
                },
            }
        }

        unreachable;
    }

    fn pushFrame(self: *Self, frame: CallFrame) !void {
        var item = StackItem{ .Frame = frame };
        try self.stack.append(item);

        // frames reset the label index since you can't jump to labels in a different function
        self.last_label_index = -1;
        self.next_label_id = 0;
    }

    fn popFrame(self: *Self) !void {
        var item = try self.pop();
        switch (item) {
            .Val => return error.TypeMismatch,
            .Label => return error.TypeMismatch,
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
                .Label => |*label| {
                    self.last_label_index = @intCast(i32, item_index);
                    self.next_label_id = label.id + 1;
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
        while (item_index >= 0) {
            var index = @intCast(usize, item_index);
            if (std.meta.activeTag(self.stack.items[index]) == .Frame) {
                return &self.stack.items[index].Frame;
            }
            item_index -= 1;
        }

        return error.MissingCallFrame;
    }

    fn popI32(self: *Self) !i32 {
        var val: Val = try self.popValue();
        switch (val) {
            ValType.I32 => |value| return value,
            else => return error.TypeMismatch,
        }
    }

    fn pushI32(self: *Self, v: i32) !void {
        var typed = Val{ .I32 = v };
        try self.pushValue(typed);
    }

    fn size(self: *const Self) usize {
        return self.stack.items.len;
    }

    stack: std.ArrayList(StackItem),
    last_label_index: i32 = -1,
    next_label_id: u32 = 0,
};

fn readBlockType(stream: *BytecodeBufferStream) !BlockTypeValue {
    var reader = stream.reader();
    const blocktype = try reader.readByte();
    const valtype_or_err = ValType.bytecodeToValtype(blocktype);
    if (std.meta.isError(valtype_or_err)) {
        if (blocktype == k_block_type_void_sentinel_byte) {
            return BlockTypeValue{ .Void = {} };
        } else {
            stream.pos -= 1;
            var index_33bit = try std.leb.readILEB128(i33, reader);
            if (index_33bit < 0) {
                return error.InvalidBytecode;
            }
            var index: u32 = @intCast(u32, index_33bit);
            return BlockTypeValue{ .TypeIndex = index };
        }
    } else {
        var valtype: ValType = valtype_or_err catch unreachable;
        return BlockTypeValue{ .ValType = valtype };
    }
}

// TODO Import, Memory, Start, Data
const Section = enum(u8) { Custom, FunctionType, Import, Function, Table, Memory, Global, Export, Start, Element, Code, Data, DataCount };

const k_function_type_sentinel_byte: u8 = 0x60;
const k_block_type_void_sentinel_byte: u8 = 0x40;

const ConstantExpression = struct {
    value: Val,

    fn decode(reader: anytype) !ConstantExpression {
        const opcode_value = try reader.readByte();
        // std.debug.print("opcode_value: 0x{X}\n", .{opcode_value});
        // const opcode = @intToEnum(Opcode, try reader.readByte());
        const opcode = @intToEnum(Opcode, opcode_value);
        const val = switch (opcode) {
            .I32_Const => Val{ .I32 = try std.leb.readILEB128(i32, reader) },
            // TODO handle i64, f32, f64, ref.null, ref.func, global.get
            else => unreachable,
        };

        const end = @intToEnum(Opcode, try reader.readByte());
        if (end != .End) {
            return ModuleDecodeError.InvalidConstantExpression;
        }

        return ConstantExpression{
            .value = val,
        };
    }

    fn resolve(self: ConstantExpression) !Val {
        return self.value;
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

const ImportDefinition = struct {
    index: u32,
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
    offset_into_encoded_bytecode: u32,
    locals: [ValType.count()]u32 = std.enums.directEnumArrayDefault(ValType, u32, 0, 0, .{}),
    size: u32,
};

const FunctionInstance = struct {
    type_def_index: u32,
    offset_into_encoded_bytecode: u32,
    locals: [ValType.count()]u32 = std.enums.directEnumArrayDefault(ValType, u32, 0, 0, .{}),
};

const ExportType = enum(u8) {
    Function = 0x00,
    Table = 0x01,
    Memory = 0x02,
    Global = 0x03,
};

const ExportDefinition = struct { name: std.ArrayList(u8), index: u32 };

const GlobalMut = enum(u8) {
    Mutable,
    Immutable,
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

    fn ensureMinSize(self: *TableInstance, size: usize) !void {
        if (self.limits.max) |max| {
            if (size > max) {
                return error.TableMaxExceeded;
            }
        }

        if (self.refs.items.len < size) {
            try self.refs.resize(size);
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

    fn init(limits: Limits) MemoryInstance {
        comptime {
            std.debug.assert(builtin.os.tag == .windows);
        }

        const max_pages = if (limits.max) |max| max else k_max_pages;

        const w = std.os.windows;
        const addr = w.VirtualAlloc(
            null,
            max_pages * k_page_size,
            w.MEM_RESERVE,
            w.PAGE_READWRITE,
        ) catch unreachable;

        var mem: []u8 = @ptrCast([*]u8, addr)[0..0];

        var instance = MemoryInstance{
            .limits = Limits{ .min = 0, .max = @intCast(u32, max_pages) },
            .mem = mem,
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
            @ptrCast(*c_void, self.mem.ptr),
            (self.limits.min + num_pages) * k_page_size,
            w.MEM_COMMIT,
            w.PAGE_READWRITE,
        ) catch return false;

        self.limits.min = @intCast(u32, total_pages);
        self.mem = self.mem.ptr[0..total_pages * k_page_size];

        return true;
    }
};

const ElementMode = enum {
    Active,
    Passive,
    Declarative,
};

const ElementDefinition = struct {
    mode: ElementMode,
    reftype: ValType,
    table_index: u32,
    offset: ?ConstantExpression,
    elems_value: std.ArrayList(Val),
    elems_expr: std.ArrayList(ConstantExpression),
};

const ElementInstance = struct {
    reftype: ValType,
    refs: std.ArrayList(Val),
};

const DataDefinition = struct {};

const DataInstance = struct {};

pub const ModuleDefinition = struct {
    const Imports = struct {
        functions: std.ArrayList(ImportDefinition),
        tables: std.ArrayList(ImportDefinition),
        memories: std.ArrayList(ImportDefinition),
        globals: std.ArrayList(ImportDefinition),
    };

    const Exports = struct {
        functions: std.ArrayList(ExportDefinition),
        tables: std.ArrayList(ExportDefinition),
        memories: std.ArrayList(ExportDefinition),
        globals: std.ArrayList(ExportDefinition),
    };

    allocator: std.mem.Allocator,

    bytecode: std.ArrayList(u8),

    types: std.ArrayList(FunctionTypeDefinition),
    imports: Imports,
    functions: std.ArrayList(FunctionDefinition),
    globals: std.ArrayList(GlobalDefinition),
    tables: std.ArrayList(TableDefinition),
    memories: std.ArrayList(MemoryDefinition),
    elements: std.ArrayList(ElementDefinition),
    exports: Exports,
    datas: std.ArrayList(DataDefinition),

    function_continuations: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList
    label_continuations: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList
    if_to_else_offsets: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList

    pub fn init(wasm: []const u8, allocator: std.mem.Allocator) !ModuleDefinition {
        var module = ModuleDefinition{
            .allocator = allocator,

            .bytecode = std.ArrayList(u8).init(allocator),

            .types = std.ArrayList(FunctionTypeDefinition).init(allocator),
            .imports = Imports{
                .functions = std.ArrayList(ImportDefinition).init(allocator),
                .tables = std.ArrayList(ImportDefinition).init(allocator),
                .memories = std.ArrayList(ImportDefinition).init(allocator),
                .globals = std.ArrayList(ImportDefinition).init(allocator),
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

            fn skipOpcodeImmediates(opcode: Opcode, stream: *BytecodeBufferStream) !void {
                // std.debug.print("skipping opcode: {}\n", .{opcode});
                var reader = stream.reader();
                _ = switch (opcode) {
                    .Local_Get => try std.leb.readULEB128(u32, reader),
                    .Local_Set => try std.leb.readULEB128(u32, reader),
                    .Local_Tee => try std.leb.readULEB128(u32, reader),
                    .Global_Get => try std.leb.readULEB128(u32, reader),
                    .Global_Set => try std.leb.readULEB128(u32, reader),
                    .I32_Const => try std.leb.readILEB128(i32, reader),
                    .Block => try readBlockType(stream),
                    .Loop => try readBlockType(stream),
                    .If => try readBlockType(stream),
                    .Branch => try std.leb.readILEB128(i32, reader),
                    .Branch_If => try std.leb.readILEB128(i32, reader),
                    .Branch_Table => {
                        const table_length = try std.leb.readULEB128(u32, reader);
                        var index: u32 = 0;
                        while (index < table_length) {
                            _ = try std.leb.readULEB128(u32, reader);
                            index += 1;
                        }
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    .Call_Indirect => {
                        _ = try std.leb.readULEB128(u32, reader); // type index
                        _ = try std.leb.readULEB128(u32, reader); // table index
                    },
                    .I32_Load => {
                        _ = try std.leb.readULEB128(u32, reader); // memarg
                    },
                    .I32_Load8_S => {
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    .I32_Load8_U => {
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    .I32_Load16_S => {
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    .I32_Load16_U => {
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    .I32_Store => {
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    .I32_Store8 => {
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    .I32_Store16 => {
                        _ = try std.leb.readULEB128(u32, reader);
                    },
                    else => {},
                };
            }
        };

        try module.bytecode.appendSlice(wasm);

        const bytecode: []const u8 = module.bytecode.items;
        var stream = std.io.fixedBufferStream(bytecode);
        var reader = stream.reader();

        // wasm header
        {
            const magic = try reader.readIntBig(u32);
            if (magic != 0x0061736D) {
                return error.InvalidMagicSignature;
            }
            const version = try reader.readIntLittle(u32);
            if (version != 1) {
                return error.UnsupportedWasmVersion;
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
                            return error.InvalidBytecode;
                        }

                        const num_params = try std.leb.readULEB128(u32, reader);

                        var func = FunctionTypeDefinition{ .num_params = num_params, .types = std.ArrayList(ValType).init(allocator) };
                        errdefer func.types.deinit();

                        var params_left = num_params;
                        while (params_left > 0) {
                            params_left -= 1;

                            var param_type = try ValType.decode(&reader);
                            try func.types.append(param_type);
                        }

                        const num_returns = try std.leb.readULEB128(u32, reader);
                        var returns_left = num_returns;
                        while (returns_left > 0) {
                            returns_left -= 1;

                            var return_type = try ValType.decode(&reader);
                            try func.types.append(return_type);
                        }

                        try module.types.append(func);
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
                            .offset_into_encoded_bytecode = 0,
                            .size = 0,
                        };

                        try module.functions.append(func);
                    }
                },
                .Table => {
                    const num_tables = try std.leb.readULEB128(u32, reader);
                    if (num_tables > 1) {
                        return error.OneTableAllowed;
                    }

                    try module.tables.ensureTotalCapacity(num_tables);

                    var table_index: u32 = 0;
                    while (table_index < num_tables) : (table_index += 1) {
                        const valtype = try ValType.decode(&reader);
                        if (valtype.isRefType() == false) {
                            return error.InvalidTableType;
                        }

                        const limits = try Limits.decode(&reader);

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
                        return ModuleDecodeError.OneMemoryAllowed;
                    }

                    try module.memories.ensureTotalCapacity(num_memories);

                    var memory_index: u32 = 0;
                    while (memory_index < num_memories) : (memory_index += 1) {
                        var limits = try Limits.decode(&reader);
                        if (limits.max) |max| {
                            if (max < limits.min) {
                                return ModuleDecodeError.MemoryInvalidMaxLimit;
                            }
                            if (max > MemoryInstance.k_max_pages) {
                                return ModuleDecodeError.MemoryMaxPagesExceeded;
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
                        var valtype = try ValType.decode(&reader);
                        var mut = @intToEnum(GlobalMut, try reader.readByte());

                        // TODO validate global references are for imports only
                        const expr = try ConstantExpression.decode(&reader);

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
                        const name_length = try std.leb.readULEB128(u32, reader);
                        var name = std.ArrayList(u8).init(allocator);
                        try name.resize(name_length);
                        errdefer name.deinit();
                        _ = try stream.read(name.items);

                        const exportType = @intToEnum(ExportType, try reader.readByte());
                        const item_index = try std.leb.readULEB128(u32, reader);
                        const def = ExportDefinition{ .name = name, .index = item_index };

                        switch (exportType) {
                            .Function => {
                                if (item_index >= module.functions.items.len) {
                                    return error.InvalidExport;
                                }
                                try module.exports.functions.append(def);
                            },
                            .Table => {
                                if (item_index >= module.tables.items.len) {
                                    return error.InvalidExport;
                                }
                                try module.exports.tables.append(def);
                            },
                            .Memory => {
                                if (item_index >= module.memories.items.len) {
                                    return error.InvalidExport;
                                }
                                try module.exports.memories.append(def);
                            },
                            .Global => {
                                if (item_index >= module.globals.items.len) {
                                    return error.InvalidExport;
                                }
                                try module.exports.globals.append(def);
                            },
                        }
                    }
                },
                //.Start
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
                                def.offset = try ConstantExpression.decode(&reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, &reader);
                            },
                            0x01 => {
                                def.mode = .Passive;
                                def.reftype = try ValType.decode(&reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, &reader);
                            },
                            0x02 => {
                                def.table_index = try std.leb.readULEB128(u32, reader);
                                def.offset = try ConstantExpression.decode(&reader);
                                def.reftype = try ValType.decode(&reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, &reader);
                            },
                            0x03 => {
                                def.mode = .Declarative;
                                def.reftype = try ValType.decode(&reader);
                                try ElementHelpers.readElemsVal(&def.elems_value, def.reftype, &reader);
                            },
                            0x04 => {
                                def.offset = try ConstantExpression.decode(&reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, &reader);
                            },
                            0x05 => {
                                def.mode = .Passive;
                                def.reftype = try ValType.decode(&reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, &reader);
                            },
                            0x06 => {
                                def.table_index = try std.leb.readULEB128(u32, reader);
                                def.offset = try ConstantExpression.decode(&reader);
                                def.reftype = try ValType.decode(&reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, &reader);
                            },
                            0x07 => {
                                def.mode = .Declarative;
                                def.reftype = try ValType.decode(&reader);
                                try ElementHelpers.readElemsExpr(&def.elems_expr, &reader);
                            },
                            else => unreachable,
                        }

                        try module.elements.append(def);
                    }
                },
                .Code => {
                    const BlockData = struct {
                        offset: u32,
                        next_instruction_offset: u32,
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
                        def.offset_into_encoded_bytecode = @intCast(u32, code_begin_pos);
                        def.size = code_size;

                        const num_locals = try std.leb.readULEB128(u32, reader);
                        var locals_index: u32 = 0;
                        while (locals_index < num_locals) {
                            locals_index += 1;
                            const n = try std.leb.readULEB128(u32, reader);
                            const local_type = try ValType.decode(&reader);
                            def.locals[@enumToInt(local_type)] = n;
                            // try vm.functions.items[code_index].locals.append(local_type);
                        }

                        const bytecode_begin_offset = @intCast(u32, stream.pos);
                        module.functions.items[code_index].offset_into_encoded_bytecode = bytecode_begin_offset;
                        try block_stack.append(BlockData{
                            .offset = bytecode_begin_offset,
                            .next_instruction_offset = bytecode_begin_offset,
                            .opcode = .Block,
                        });

                        var parsing_code = true;
                        while (parsing_code) {
                            const instruction_byte = try reader.readByte();
                            // std.debug.print(">>>> 0x{X}\n", .{instruction_byte});
                            const opcode = @intToEnum(Opcode, instruction_byte);
                            // std.debug.print(">>>> {}\n", .{opcode});

                            const parsing_offset = @intCast(u32, stream.pos - 1);
                            try DecodeHelpers.skipOpcodeImmediates(opcode, &stream);

                            if (opcode.expectsEnd()) {
                                try block_stack.append(BlockData{
                                    .offset = parsing_offset,
                                    .next_instruction_offset = @intCast(u32, stream.pos),
                                    .opcode = opcode,
                                });
                            } else if (opcode == .Else) {
                                const block: *const BlockData = &block_stack.items[block_stack.items.len - 1];
                                try module.if_to_else_offsets.putNoClobber(block.offset, parsing_offset);
                            } else if (opcode == .End) {
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
                                        // std.debug.print("adding loop continuation for offset {}: {}\n", .{block.offset, block.offset});
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
                            return error.InvalidBytecode;
                        }

                        code_index += 1;
                    }
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
        self.bytecode.deinit();

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

pub const FunctionImport = struct {
    name: []const u8,
    // TODO
};

pub const TableImport = struct {
    name: []const u8,
};

pub const MemoryImport = struct {
    name: []const u8,
};

pub const GlobalImport = struct {
    name: []const u8,
};

pub const ModuleImports = struct {
    name: []const u8,
    functions: std.ArrayList(FunctionImport),
    tables: std.ArrayList(FunctionImport),
    memories: std.ArrayList(FunctionImport),
    globals: std.ArrayList(GlobalImport),
};

pub const PackageImports = struct {
    imports: std.ArrayList(ModuleImports),
};

pub const Store = struct {
    functions: std.ArrayList(FunctionInstance),
    tables: std.ArrayList(TableInstance),
    memories: std.ArrayList(MemoryInstance),
    globals: std.ArrayList(GlobalInstance),
    elements: std.ArrayList(ElementInstance),
    datas: std.ArrayList(DataInstance),

    module_def: *const ModuleDefinition, // temp

    fn init(module_def: *const ModuleDefinition, _: *PackageImports, allocator: std.mem.Allocator) !Store {
        var store = Store{
            .functions = std.ArrayList(FunctionInstance).init(allocator),
            .tables = std.ArrayList(TableInstance).init(allocator),
            .memories = std.ArrayList(MemoryInstance).init(allocator),
            .globals = std.ArrayList(GlobalInstance).init(allocator),
            .elements = std.ArrayList(ElementInstance).init(allocator),
            .datas = std.ArrayList(DataInstance).init(allocator),

            .module_def = module_def,
        };
        errdefer store.deinit();

        try store.functions.ensureTotalCapacity(module_def.imports.functions.items.len + module_def.functions.items.len);
        for (module_def.imports.functions.items) |_| {
            var f = FunctionInstance{
                .type_def_index = 0,
                .offset_into_encoded_bytecode = 0,
            };
            try store.functions.append(f);
        }
        for (module_def.functions.items) |*def_func| {
            var f = FunctionInstance{
                .type_def_index = def_func.type_index,
                .offset_into_encoded_bytecode = def_func.offset_into_encoded_bytecode,
                .locals = def_func.locals,
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
        for (module_def.memories.items) |memory| {
            var m = MemoryInstance.init(memory.limits);
            if (memory.limits.min > 0) {
                if (m.grow(memory.limits.min) == false) {
                    return error.OutOfMemory;
                }
            }
            try store.memories.append(m);
        }

        try store.globals.ensureTotalCapacity(module_def.imports.globals.items.len + module_def.globals.items.len);
        for (module_def.imports.globals.items) |_| {
            var g = GlobalInstance{ .mut = GlobalMut.Immutable, .value = Val{
                .I32 = 0,
            } };
            try store.globals.append(g);
        }
        for (module_def.globals.items) |global| {
            var g = GlobalInstance{
                .mut = global.mut,
                .value = try global.expr.resolve(),
            };
            try store.globals.append(g);
        }

        try store.datas.ensureTotalCapacity(module_def.datas.items.len);
        for (module_def.datas.items) |_| {}

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
        self.datas.deinit();
    }
};

pub const ModuleInstance = struct {
    allocator: std.mem.Allocator,
    stack: Stack,
    store: Store,
    module_def: *const ModuleDefinition,

    pub fn init(module_def: *const ModuleDefinition, imports: *PackageImports, allocator: std.mem.Allocator) !ModuleInstance {
        return ModuleInstance{
            .allocator = allocator,
            .stack = Stack.init(allocator),
            .store = try Store.init(module_def, imports, allocator),
            .module_def = module_def,
        };
    }

    pub fn deinit(self: *ModuleInstance) void {
        self.stack.deinit();
        self.store.deinit();
    }

    pub fn invoke(self: *ModuleInstance, func_name: []const u8, params: []const Val, returns: []Val) !void {
        for (self.module_def.exports.functions.items) |func_export| {
            if (std.mem.eql(u8, func_name, func_export.name.items)) {
                const func: FunctionInstance = self.store.functions.items[func_export.index + self.module_def.imports.functions.items.len];
                const func_type_params: []const ValType = self.module_def.types.items[func.type_def_index].getParams();

                if (params.len != func_type_params.len) {
                    // std.debug.print("params.len: {}, func_type_params.len: {}\n", .{params.len, func_type_params.len});
                    // std.debug.print("params: {s}, func_type_params: {s}\n", .{params, func_type_params});
                    return error.TypeMismatch;
                }

                for (params) |param, i| {
                    if (std.meta.activeTag(param) != func_type_params[i]) {
                        return error.TypeMismatch;
                    }
                }

                var locals = std.ArrayList(Val).init(self.allocator); // gets deinited when popFrame() is called
                try locals.resize(func.locals.len);
                for (params) |v, i| {
                    locals.items[i] = v;
                }

                // TODO move function continuation data into FunctionDefinition
                var function_continuation = self.module_def.function_continuations.get(func.offset_into_encoded_bytecode) orelse return error.InvalidFunction;

                try self.stack.pushFrame(CallFrame{
                    .func = &func,
                    .locals = locals,
                });
                try self.stack.pushLabel(BlockTypeValue{ .TypeIndex = func.type_def_index }, function_continuation);
                try self.executeWasm(self.module_def.bytecode.items, func.offset_into_encoded_bytecode);

                if (self.stack.size() != returns.len) {
                    std.debug.print("stack size: {}, returns.len: {}\n", .{ self.stack.size(), returns.len });
                    return error.TypeMismatch;
                }

                if (returns.len > 0) {
                    var index: i32 = @intCast(i32, returns.len - 1);
                    while (index >= 0) {
                        // std.debug.print("stack size: {}, index: {}\n", .{self.stack.size(), index});
                        returns[@intCast(usize, index)] = try self.stack.popValue();
                        index -= 1;
                    }
                }
                return;
            }
        }

        return error.UnknownExport;
    }

    fn executeWasm(self: *ModuleInstance, bytecode: []const u8, offset: u32) !void {
        var stream = std.io.fixedBufferStream(bytecode);
        try stream.seekTo(offset);
        var reader = stream.reader();

        // TODO use a linear allocator for scratch allocations that gets reset on each loop iteration

        while (stream.pos < stream.buffer.len) {
            const instruction_offset: u32 = @intCast(u32, stream.pos);
            const opcode = @intToEnum(Opcode, try reader.readByte());

            // std.debug.print("found opcode: {} (pos {})\n", .{ opcode, stream.pos });

            switch (opcode) {
                Opcode.Unreachable => {
                    return error.Unreachable;
                },
                Opcode.Noop => {},
                Opcode.Block => {
                    try self.enterBlock(&stream, instruction_offset);
                },
                Opcode.Loop => {
                    try self.enterBlock(&stream, instruction_offset);
                },
                Opcode.If => {
                    var condition = try self.stack.popI32();
                    if (condition != 0) {
                        try self.enterBlock(&stream, instruction_offset);
                    } else if (self.module_def.if_to_else_offsets.get(instruction_offset)) |else_offset| {
                        // +1 to skip the else opcode, since it's treated as an End for the If block.
                        try self.enterBlock(&stream, else_offset);
                        try stream.seekTo(else_offset + 1);
                    } else {
                        const continuation = self.module_def.label_continuations.get(instruction_offset) orelse return error.InvalidLabel;
                        try stream.seekTo(continuation);
                    }
                },
                Opcode.Else => {
                    // getting here means we reached the end of the if opcode chain, so skip to the true end opcode
                    const end_offset = self.module_def.label_continuations.get(instruction_offset) orelse return error.InvalidLabel;
                    try stream.seekTo(end_offset);
                },
                Opcode.End => {
                    var returns = std.ArrayList(Val).init(self.allocator);
                    defer returns.deinit();

                    // id 0 means this is the end of a function, otherwise it's the end of a block
                    const label_ptr: *const Label = self.stack.topLabel();
                    if (label_ptr.id != 0) {
                        try popValues(&returns, &self.stack, self.getReturnTypesFromBlockType(label_ptr.blocktype));
                        _ = try self.stack.popLabel();
                        try pushValues(returns.items, &self.stack);
                    } else {
                        var frame: *const CallFrame = try self.stack.findCurrentFrame();
                        const returnTypes: []const ValType = self.module_def.types.items[frame.func.type_def_index].getReturns();

                        try popValues(&returns, &self.stack, returnTypes);
                        var label = try self.stack.popLabel();
                        try self.stack.popFrame();
                        const is_root_function = (self.stack.size() == 0);
                        try pushValues(returns.items, &self.stack);

                        // std.debug.print("returning from func call... is root: {}\n", .{is_root_function});
                        if (is_root_function) {
                            return;
                        } else {
                            try stream.seekTo(label.continuation);
                        }
                    }
                },
                Opcode.Branch => {
                    const label_id = try std.leb.readULEB128(u32, reader);
                    try self.branch(&stream, label_id);
                },
                Opcode.Branch_If => {
                    const label_id = try std.leb.readULEB128(u32, reader);
                    const v = try self.stack.popI32();
                    // std.debug.print("branch_if stack value: {}, target id: {}\n", .{v, label_id});
                    if (v != 0) {
                        try self.branch(&stream, label_id);
                    }
                },
                Opcode.Branch_Table => {
                    var label_ids = std.ArrayList(u32).init(self.allocator);
                    defer label_ids.deinit();

                    const table_length = try std.leb.readULEB128(u32, reader);
                    try label_ids.ensureTotalCapacity(table_length);

                    while (label_ids.items.len < table_length) {
                        const label_id = try std.leb.readULEB128(u32, reader);
                        try label_ids.append(label_id);
                    }
                    const fallback_id = try std.leb.readULEB128(u32, reader);

                    var label_index = @intCast(usize, try self.stack.popI32());
                    if (label_index < label_ids.items.len) {
                        try self.branch(&stream, label_ids.items[label_index]);
                    } else {
                        try self.branch(&stream, fallback_id);
                    }
                },
                Opcode.Return => {
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    const returnTypes: []const ValType = self.module_def.types.items[frame.func.type_def_index].getReturns();

                    var returns = std.ArrayList(Val).init(self.allocator);
                    defer returns.deinit();
                    try returns.ensureTotalCapacity(returnTypes.len);

                    while (returns.items.len < returnTypes.len) {
                        var value = try self.stack.popValue();
                        if (std.meta.activeTag(value) != returnTypes[returns.items.len]) {
                            return error.TypeMismatch;
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

                    // std.debug.print("pushing returns: {s}\n", .{returns});
                    while (returns.items.len > 0) {
                        var value = returns.orderedRemove(returns.items.len - 1);
                        try self.stack.pushValue(value);
                    }

                    // std.debug.print("returning from func call... is root: {}\n", .{is_root_function});
                    if (is_root_function) {
                        return;
                    } else {
                        try stream.seekTo(last_label.continuation);
                    }
                },
                Opcode.Call => {
                    const func_index = try std.leb.readULEB128(u32, reader);
                    const func: *const FunctionInstance = &self.store.functions.items[@intCast(usize, func_index)];
                    const functype: *const FunctionTypeDefinition = &self.module_def.types.items[func.type_def_index];

                    var frame = CallFrame{
                        .func = func,
                        .locals = std.ArrayList(Val).init(self.allocator),
                    };

                    const param_types: []const ValType = functype.getParams();
                    try frame.locals.resize(param_types.len);

                    var param_index = param_types.len;
                    while (param_index > 0) {
                        param_index -= 1;
                        var value = try self.stack.popValue();
                        if (std.meta.activeTag(value) != param_types[param_index]) {
                            return error.TypeMismatch;
                        }
                        frame.locals.items[param_index] = value;
                    }

                    const continuation = @intCast(u32, stream.pos);

                    try self.stack.pushFrame(frame);
                    try self.stack.pushLabel(BlockTypeValue{ .TypeIndex = func.type_def_index }, continuation);
                    try stream.seekTo(func.offset_into_encoded_bytecode);
                },
                Opcode.Call_Indirect => {
                    // var type_index = try std.leb.readULEB128(u32, reader);
                    // var table_index = try std.leb.readULEB128(u32, reader);                    
                },
                Opcode.Drop => {
                    _ = try self.stack.popValue();
                },
                Opcode.Select => {
                    var boolean = try self.stack.popValue();
                    var v2 = try self.stack.popValue();
                    var v1 = try self.stack.popValue();

                    if (builtin.mode == .Debug) {
                        if (std.meta.activeTag(boolean) != ValType.I32) {
                            return error.TypeMismatch;
                        } else if (std.meta.activeTag(v1) != std.meta.activeTag(v2)) {
                            return error.TypeMismatch;
                        }
                    }

                    if (boolean.I32 != 0) {
                        try self.stack.pushValue(v1);
                    } else {
                        try self.stack.pushValue(v2);
                    }
                },
                Opcode.Local_Get => {
                    var locals_index = try std.leb.readULEB128(u32, reader);
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    var v: Val = frame.locals.items[locals_index];
                    try self.stack.pushValue(v);
                },
                Opcode.Local_Set => {
                    var locals_index = try std.leb.readULEB128(u32, reader);
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    var v: Val = try self.stack.popValue();
                    frame.locals.items[locals_index] = v;
                },
                Opcode.Local_Tee => {
                    var locals_index = try std.leb.readULEB128(u32, reader);
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    var v: Val = try self.stack.topValue();
                    frame.locals.items[locals_index] = v;
                },
                Opcode.Global_Get => {
                    var global_index = try std.leb.readULEB128(u32, reader);
                    var global = &self.store.globals.items[global_index];
                    try self.stack.pushValue(global.value);
                },
                Opcode.Global_Set => {
                    var global_index = try std.leb.readULEB128(u32, reader);
                    var global = &self.store.globals.items[global_index];
                    if (global.mut == GlobalMut.Immutable) {
                        return error.AttemptToSetImmutable;
                    }
                    global.value = try self.stack.popValue();
                },
                Opcode.I32_Load => {},
                Opcode.I32_Load8_S => {},
                Opcode.I32_Load8_U => {},
                Opcode.I32_Load16_S => {},
                Opcode.I32_Load16_U => {},
                Opcode.I32_Store => {},
                Opcode.I32_Store8 => {},
                Opcode.I32_Store16 => {},
                Opcode.Memory_Size => {
                    var immediate = try reader.readByte();
                    if (immediate != 0x00) {
                        return ModuleDecodeError.InvalidBytecode;
                    }

                    const memory_index:usize = 0;

                    if (self.store.memories.items.len <= memory_index) {
                        return InterpreterError.MemoryInvalidIndex;
                    }

                    const num_pages: i32 = @intCast(i32, self.store.memories.items[memory_index].limits.min);

                    try self.stack.pushI32(num_pages);
                },
                Opcode.Memory_Grow => {
                    var immediate = try reader.readByte();
                    if (immediate != 0x00) {
                        return ModuleDecodeError.InvalidBytecode;
                    }
                    
                    const memory_index: usize = 0;

                    if (self.store.memories.items.len <= memory_index) {
                        return InterpreterError.MemoryInvalidIndex;
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
                    var v: i32 = try std.leb.readILEB128(i32, reader);
                    try self.stack.pushI32(v);
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
                    var value = try std.math.divTrunc(i32, v1, v2);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Div_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value_unsigned = try std.math.divFloor(u32, v1, v2);
                    var value = @bitCast(i32, value_unsigned);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Rem_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var denom = try std.math.absInt(v2);
                    var value = try std.math.rem(i32, v1, denom);
                    try self.stack.pushI32(value);
                },
                Opcode.I32_Rem_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 % v2);
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
                Opcode.I32_Extend8_S => {
                    var v = try self.stack.popI32();
                    var v_i8 = @truncate(i8, v);
                    var v_extended: i32 = v_i8;
                    try self.stack.pushI32(v_extended);
                },
                Opcode.I32_Extend16_S => {
                    var v = try self.stack.popI32();
                    var v_i16 = @truncate(i16, v);
                    var v_extended: i32 = v_i16;
                    try self.stack.pushI32(v_extended);
                },
            }
        }
    }

    fn enterBlock(self: *ModuleInstance, stream: *BytecodeBufferStream, label_offset: u32) !void {
        var blocktype = try readBlockType(stream);

        const continuation = self.module_def.label_continuations.get(label_offset) orelse return error.InvalidLabel;
        try self.stack.pushLabel(blocktype, continuation);
    }

    fn branch(self: *ModuleInstance, stream: *BytecodeBufferStream, label_id: u32) !void {
        // std.debug.print("branching to label {}\n", .{label_id});
        const label: *const Label = try self.stack.findLabel(label_id);
        if (label.last_label_index == -1) {
            return error.LabelMismatch; // can't branch to the end of functions - that's the return opcode's job
        }
        const label_stack_id = label.id;
        const continuation = label.continuation;

        // std.debug.print("found label: {}\n", .{label});

        var args = std.ArrayList(Val).init(self.allocator);
        defer args.deinit();

        try popValues(&args, &self.stack, self.getReturnTypesFromBlockType(label.blocktype));

        while (true) {
            var topItem = try self.stack.top();
            switch (std.meta.activeTag(topItem.*)) {
                .Val => {
                    _ = try self.stack.popValue();
                },
                .Frame => {
                    return error.InvalidLabel;
                },
                .Label => {
                    const popped_label: Label = try self.stack.popLabel();
                    if (popped_label.id == label_stack_id) {
                        break;
                    }
                },
            }
        }

        try pushValues(args.items, &self.stack);

        // std.debug.print("branching to continuation: {}\n", .{continuation});
        try stream.seekTo(continuation);
    }

    fn getReturnTypesFromBlockType(self: *ModuleInstance, blocktype: BlockTypeValue) []const ValType {
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
            if (types[returns.items.len] != std.meta.activeTag(item)) {
                // std.debug.print("popValues mismatch: required: {s}, got {}\n", .{types, item});
                return error.TypeMismatch;
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
