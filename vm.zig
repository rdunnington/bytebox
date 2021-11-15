const std = @import("std");
const builtin = @import("builtin");

const VmParseError = error{
    UnsupportedWasmVersion,
    InvalidMagicSignature,
    InvalidBytecode,
    InvalidExport,
    InvalidGlobalInit,
    InvalidLabel,
};

const VMError = error{
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
};

const Instruction = enum(u8) {
    Unreachable = 0x00,
    Noop = 0x01,
    Block = 0x02,
    End = 0x0B,
    Branch = 0x0C,
    Branch_If = 0x0D,
    Return = 0x0F,
    Call = 0x10,
    Drop = 0x1A,
    Select = 0x1B,
    Local_Get = 0x20,
    Local_Set = 0x21,
    Local_Tee = 0x22,
    Global_Get = 0x23,
    Global_Set = 0x24,
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
};

const BytecodeBufferStream = std.io.FixedBufferStream([]const u8);

fn skipInstruction(instruction:Instruction, stream: *BytecodeBufferStream) !void {
    var reader = stream.reader();
    _ = switch (instruction) {
        .Local_Get => try std.leb.readULEB128(u32, reader),
        .Local_Set => try std.leb.readULEB128(u32, reader),
        .Local_Tee => try std.leb.readULEB128(u32, reader),
        .Global_Get => try std.leb.readULEB128(u32, reader),
        .Global_Set => try std.leb.readULEB128(u32, reader),
        .I32_Const => try std.leb.readILEB128(i32, reader),
        .Block => {
            _ = try VmState.readBlockType(stream);
        },
        .Branch => try std.leb.readILEB128(i32, reader),
        .Branch_If => try std.leb.readILEB128(i32, reader),
        else => {}
    };
}

fn isInstructionMultiByte(instruction:Instruction) bool {
    const v = switch (instruction) {
        .Local_Get => true,
        .Local_Set => true,
        .Local_Tee => true,
        .Global_Get => true,
        .Global_Set => true,
        .I32_Const => true,
        .Block => true,
        .Branch => true,
        .Branch_If => true,
        else => false,
    };
    return v;
}

fn doesInstructionExpectEnd(instruction:Instruction) bool {
    switch (instruction) {
        .Block => return true,
        else => return false,
    }
}

const Type = enum(u8) {
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
    // FuncRef = 0x70,
    // ExternRef = 0x6F,
};

const TypedValue = union(Type) {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
};

const GlobalValue = struct {
    const Mut = enum(u8) {
        Mutable,
        Immutable,
    };

    mut: Mut,
    value: TypedValue,
};

// others such as null ref, funcref, or an imported global
const GlobalValueInitTag = enum {
    Value,
};
const GlobalValueInitOptions = union(GlobalValueInitTag) {
    Value: TypedValue,
};

const BlockType = enum {
    Void,
    Valtype,
    TypeIndex,
};

const BlockTypeValue = union(BlockType) {
    Void: void,
    Valtype: Type,
    TypeIndex: u32,
};

const Label = struct{
    id:u32,
    arity: u32, // the number of args that need to be pushed onto the stack after this label is popped
    continuation: u32,
    last_label_index: i32,
};

const CallFrame = struct {
    func: *const Function,
    locals: std.ArrayList(TypedValue),
};

const StackItemType = enum(u8) {
    Value,
    Label,
    Frame,
};
const StackItem = union(StackItemType) {
    Value: TypedValue,
    Label: Label,
    Frame: CallFrame,
};

const Stack = struct {
    const Self = @This();

    fn init(allocator: *std.mem.Allocator) Self {
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

    fn topValue(self: *const Self) !TypedValue {
        var item = try self.top();
        switch (item.*) {
            .Value => |v| return v,
            .Label => return error.TypeMismatch,
            .Frame => return error.TypeMismatch,
        }
    }

    fn pushValue(self: *Self, v: TypedValue) !void {
        var item = StackItem{.Value = v};
        try self.stack.append(item);
    }

    fn popValue(self: *Self) !TypedValue {
        var item = try self.pop();
        switch (item) {
            .Value => |v| return v,
            .Label => return error.TypeMismatch,
            .Frame => return error.TypeMismatch,
        }
    }

    fn pushLabel(self:*Self, arity: u32, continuation:u32) !void {
        const id:u32 = self.next_label_id;
        var item = StackItem{.Label = .{
            .id = id,
            .arity = arity,
            .continuation = continuation,
            .last_label_index = self.last_label_index,
        }};
        try self.stack.append(item);

        self.last_label_index = @intCast(i32, self.stack.items.len) - 1;
        self.next_label_id += 1;
    }

    fn popLabel(self: *Self) !Label {
        var item = try self.pop();
        var label = switch (item) {
            .Value => return error.TypeMismatch,
            .Label => |label| label,
            .Frame => return error.TypeMismatch,
        };

        self.last_label_index = label.last_label_index;
        self.next_label_id = 0;

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
            switch(self.stack.items[@intCast(usize, label_index)]) {
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
        var item = StackItem{.Frame = frame};
        try self.stack.append(item);

        // frames reset the label index since you can't jump to labels in a different function
        self.last_label_index = -1;
        self.next_label_id = 0;
    }

    fn popFrame(self: *Self) !void {
        var item = try self.pop();
        switch (item) {
            .Value => return error.TypeMismatch,
            .Label => return error.TypeMismatch,
            .Frame => |*frame| {
                frame.locals.deinit();
            },
        }

        // have to do a linear search since we don't know what the last index was
        var item_index = self.stack.items.len;
        while (item_index > 0) {
            item_index -= 1;
            switch(self.stack.items[item_index]) {
                .Value => {},
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
        var item_index:i32 = @intCast(i32, self.stack.items.len) - 1;
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
        var typed: TypedValue = try self.popValue();
        switch (typed) {
            Type.I32 => |value| return value,
            else => return error.TypeMismatch,
        }
    }

    fn pushI32(self: *Self, v: i32) !void {
        var typed = TypedValue{ .I32 = v };
        try self.pushValue(typed);
    }

    fn size(self: *const Self) usize {
        return self.stack.items.len;
    }

    stack: std.ArrayList(StackItem),
    last_label_index: i32 = -1,
    next_label_id: u32 = 0,
};

const Section = enum(u8) { Custom, FunctionType, Import, Function, Table, Memory, Global, Export, Start, Element, Code, Data, DataCount };

const function_type_sentinel_byte: u8 = 0x60;
const block_type_void_sentinel_byte: u8 = 0x40;
const max_global_init_size:usize = 32;

const FunctionType = struct {
    types: std.ArrayList(Type),
    numParams: u32,

    fn getParams(self: *const FunctionType) []const Type {
        return self.types.items[0..self.numParams];
    }
    fn getReturns(self: *const FunctionType) []const Type {
        return self.types.items[self.numParams..];
    }
};

const FunctionTypeContext = struct {
    const Self = @This();

    pub fn hash(_: Self, f: *FunctionType) u64 {
        var seed: u64 = 0;
        if (f.types.items.len > 0) {
            seed = std.hash.Murmur2_64.hash(std.mem.sliceAsBytes(f.types.items));
        }
        return std.hash.Murmur2_64.hashWithSeed(std.mem.asBytes(&f.numParams), seed);
    }

    pub fn eql(_: Self, a: *FunctionType, b: *FunctionType) bool {
        if (a.numParams != b.numParams or a.types.items.len != b.types.items.len) {
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

    fn less(context: Self, a: *FunctionType, b: *FunctionType) bool {
        var ord = Self.order(context, a, b);
        return ord == std.math.Order.lt;
    }

    fn order(context: Self, a: *FunctionType, b: *FunctionType) std.math.Order {
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

const Function = struct {
    typeIndex: u32,
    bytecodeOffset: u32,
    locals: std.ArrayList(Type),
};

const ExportType = enum(u8) {
    Function = 0x00,
    Table = 0x01,
    Memory = 0x02,
    Global = 0x03,
};

const Export = struct { name: std.ArrayList(u8), index: u32 };

const Exports = struct {
    functions: std.ArrayList(Export),
    tables: std.ArrayList(Export),
    memories: std.ArrayList(Export),
    globals: std.ArrayList(Export),
};

const VmState = struct {
    const Self = @This();

    allocator: *std.mem.Allocator,
    bytecode: []const u8,
    bytecode_mem_usage: std.ArrayList(u8),
    types: std.ArrayList(FunctionType),
    functions: std.ArrayList(Function),
    globals: std.ArrayList(GlobalValue),
    exports: Exports,

    function_continuations: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList
    label_continuations: std.AutoHashMap(u32, u32), // todo use a sorted ArrayList
    stack: Stack,

    const BytecodeMemUsage = enum {
        UseExisting,
        Copy,
    };

    fn parseWasm(externalBytecode: []const u8, bytecodeMemUsage: BytecodeMemUsage, allocator: *std.mem.Allocator) !Self {
        var bytecode_mem_usage = std.ArrayList(u8).init(allocator);
        errdefer bytecode_mem_usage.deinit();

        var bytecode: []const u8 = undefined;
        switch (bytecodeMemUsage) {
            .UseExisting => bytecode = externalBytecode,
            .Copy => {
                try bytecode_mem_usage.appendSlice(externalBytecode);
                bytecode = bytecode_mem_usage.items;
            },
        }

        var vm = Self{
            .allocator = allocator,
            .bytecode = bytecode,
            .bytecode_mem_usage = bytecode_mem_usage,
            .types = std.ArrayList(FunctionType).init(allocator),
            .functions = std.ArrayList(Function).init(allocator),
            .globals = std.ArrayList(GlobalValue).init(allocator),
            .exports = Exports{
                .functions = std.ArrayList(Export).init(allocator),
                .tables = std.ArrayList(Export).init(allocator),
                .memories = std.ArrayList(Export).init(allocator),
                .globals = std.ArrayList(Export).init(allocator),
            },
            .function_continuations = std.AutoHashMap(u32, u32).init(allocator),
            .label_continuations = std.AutoHashMap(u32, u32).init(allocator), // map of label offset to continuation offset.
            .stack = Stack.init(allocator),
        };
        errdefer vm.deinit();

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
            switch (section_id) {
                .FunctionType => {
                    // std.debug.print("parseWasm: section: FunctionType\n", .{});
                    const num_types = try std.leb.readULEB128(u32, reader);
                    var types_index:u32 = 0;
                    while (types_index < num_types) {
                        const sentinel = try reader.readByte();
                        if (sentinel != function_type_sentinel_byte) {
                            return error.InvalidBytecode;
                        }

                        const num_params = try std.leb.readULEB128(u32, reader);

                        var func = FunctionType{ .numParams = num_params, .types = std.ArrayList(Type).init(allocator) };
                        errdefer func.types.deinit();

                        var params_left = num_params;
                        while (params_left > 0) {
                            params_left -= 1;

                            var param_type = @intToEnum(Type, try reader.readByte());
                            try func.types.append(param_type);
                        }

                        const num_returns = try std.leb.readULEB128(u32, reader);
                        var returns_left = num_returns;
                        while (returns_left > 0) {
                            returns_left -= 1;

                            var return_type = @intToEnum(Type, try reader.readByte());
                            try func.types.append(return_type);
                        }

                        try vm.types.append(func);

                        types_index += 1;
                    }
                },
                .Function => {
                    // std.debug.print("parseWasm: section: Function\n", .{});

                    const num_funcs = try std.leb.readULEB128(u32, reader);
                    var func_index:u32 = 0;
                    while (func_index < num_funcs) {
                        var func = Function{
                            .typeIndex = try std.leb.readULEB128(u32, reader),
                            .bytecodeOffset = 0, // we'll fix these up later when we find them in the Code section
                            .locals = std.ArrayList(Type).init(allocator),
                        };
                        errdefer func.locals.deinit();
                        try vm.functions.append(func);

                        func_index += 1;
                    }
                },
                .Global => {
                    const num_globals = try std.leb.readULEB128(u32, reader);

                    var global_index: u32 = 0;
                    while (global_index < num_globals) {
                        var mut = @intToEnum(GlobalValue.Mut, try reader.readByte());
                        var valtype = @intToEnum(Type, try reader.readByte());

                        var init = std.ArrayList(u8).init(allocator);
                        defer init.deinit();
                        try reader.readUntilDelimiterArrayList(&init, @enumToInt(Instruction.End), max_global_init_size);

                        // TODO validate init instructions are a constant expression
                        // TODO validate global references are for imports only
                        try vm.executeWasm(init.items, 0);
                        if (vm.stack.size() != 1) {
                            return error.InvalidGlobalInit;
                        }
                        var value = try vm.stack.popValue();

                        if (std.meta.activeTag(value) != valtype) {
                            return error.InvalidGlobalInit;
                        }

                        try vm.globals.append(GlobalValue{
                            .value = value,
                            .mut = mut,
                        });

                        global_index += 1;
                    }
                },
                .Export => {
                    // std.debug.print("parseWasm: section: Export\n", .{});

                    const num_exports = try std.leb.readULEB128(u32, reader);

                    var export_index:u32 = 0;
                    while (export_index < num_exports) {
                        const name_length = try std.leb.readULEB128(u32, reader);
                        var name = std.ArrayList(u8).init(allocator);
                        try name.resize(name_length);
                        errdefer name.deinit();
                        _ = try stream.read(name.items);

                        const exportType = @intToEnum(ExportType, try reader.readByte());
                        const exportIndex = try std.leb.readULEB128(u32, reader);
                        switch (exportType) {
                            .Function => {
                                if (exportIndex >= vm.functions.items.len) {
                                    return error.InvalidExport;
                                }
                                const export_ = Export{ .name = name, .index = exportIndex };
                                try vm.exports.functions.append(export_);
                            },
                            .Global => {
                                if (exportIndex >= vm.globals.items.len) {
                                    return error.InvalidExport;
                                }
                                const export_ = Export{ .name = name, .index = exportIndex };
                                try vm.exports.globals.append(export_);
                            },
                            else => {},
                        }

                        export_index += 1;
                    }
                },

                .Code => {
                    // std.debug.print("parseWasm: section: Code\n", .{});

                    var continuation_stack = std.ArrayList(u32).init(allocator);
                    defer continuation_stack.deinit();

                    const num_codes = try std.leb.readULEB128(u32, reader);
                    var code_index: u32 = 0;
                    while (code_index < num_codes) {
                        // std.debug.print(">>> parsing code index {}\n", .{code_index});
                        const code_size = try std.leb.readULEB128(u32, reader);
                        const code_begin_pos = stream.pos;

                        const num_locals = try std.leb.readULEB128(u32, reader);
                        var locals_index: u32 = 0;
                        while (locals_index < num_locals) {
                            locals_index += 1;
                            const local_type = @intToEnum(Type, try reader.readByte());
                            try vm.functions.items[code_index].locals.append(local_type);
                        }

                        const bytecode_begin_offset = @intCast(u32, stream.pos);
                        vm.functions.items[code_index].bytecodeOffset = bytecode_begin_offset;
                        try continuation_stack.append(0); // marks the beginning of the function

                        var parsing_code = true;
                        while (parsing_code) {
                            const instruction_byte = try reader.readByte();
                            const instruction = @intToEnum(Instruction, instruction_byte);
                            // std.debug.print(">>>> {}\n", .{instruction});

                            if (doesInstructionExpectEnd(instruction)) {
                                const instruction_offset = @intCast(u32, stream.pos - 1);
                                try continuation_stack.append(instruction_offset);
                            } else if (instruction == .End) {
                                const continuation = @intCast(u32, stream.pos - 1);
                                if (continuation_stack.items.len == 1) {
                                    // std.debug.print("found the end\n", .{});
                                    parsing_code = false;

                                    try vm.function_continuations.putNoClobber(bytecode_begin_offset, continuation);
                                    continuation_stack.clearRetainingCapacity();
                                    // std.debug.print("adding function continuation for offset {}: {}\n", .{bytecode_begin_offset, continuation});
                                } else {
                                    const instruction_offset: u32 = continuation_stack.orderedRemove(continuation_stack.items.len - 1);
                                    try vm.label_continuations.putNoClobber(instruction_offset, continuation);
                                    // std.debug.print("adding label continuation for offset {}: {}\n", .{instruction_offset, continuation});
                                }
                            }

                            try skipInstruction(instruction, &stream);
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
                    std.debug.print("Skipping module section {}", .{section_id});
                    try stream.seekBy(@intCast(i64, size_bytes));
                },
            }
        }

        return vm;
    }

    fn deinit(self: *Self) void {
        for (self.types.items) |item| {
            item.types.deinit();
        }
        for (self.functions.items) |item| {
            item.locals.deinit();
        }

        for (self.exports.functions.items) |item| {
            item.name.deinit();
        }
        for (self.exports.tables.items) |item| {
            item.name.deinit();
        }
        for (self.exports.memories.items) |item| {
            item.name.deinit();
        }
        for (self.exports.globals.items) |item| {
            item.name.deinit();
        }

        self.exports.functions.deinit();
        self.exports.tables.deinit();
        self.exports.memories.deinit();
        self.exports.globals.deinit();

        self.types.deinit();
        self.functions.deinit();
        self.globals.deinit();
        self.function_continuations.deinit();
        self.label_continuations.deinit();
        self.stack.deinit();
    }

    fn callFunc(self: *Self, name: []const u8, params: []const TypedValue, returns: []TypedValue) !void {
        for (self.exports.functions.items) |funcExport| {
            if (std.mem.eql(u8, name, funcExport.name.items)) {
                const func: Function = self.functions.items[funcExport.index];
                const funcTypeParams: []const Type = self.types.items[func.typeIndex].getParams();

                if (params.len != funcTypeParams.len) {
                    // std.debug.print("params.len: {}, funcTypeParams.len: {}\n", .{params.len, funcTypeParams.len});
                    // std.debug.print("params: {s}, funcTypeParams: {s}\n", .{params, funcTypeParams});
                    return error.TypeMismatch;
                }

                for (params) |param, i| {
                    if (std.meta.activeTag(param) != funcTypeParams[i]) {
                        return error.TypeMismatch;
                    }
                }

                var locals = std.ArrayList(TypedValue).init(self.allocator);
                try locals.resize(func.locals.items.len);
                for (params) |v, i| {
                    locals.items[i] = v;
                }

                var function_continuation = self.function_continuations.get(func.bytecodeOffset) orelse return error.InvalidFunction;

                try self.stack.pushFrame(CallFrame{.func = &func, .locals = locals,});
                try self.stack.pushLabel(@intCast(u32, returns.len), function_continuation);
                try self.executeWasm(self.bytecode, func.bytecodeOffset);

                if (self.stack.size() != returns.len) {
                    std.debug.print("stack size: {}, returns.len: {}\n", .{self.stack.size(), returns.len});
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

    fn readBlockType(stream: *BytecodeBufferStream) !BlockTypeValue {
        var reader = stream.reader();
        const blocktype = try reader.readByte();
        const valtype_or_err = std.meta.intToEnum(Type, blocktype);
        if (std.meta.isError(valtype_or_err)) {
            if (blocktype == block_type_void_sentinel_byte) {
                return BlockTypeValue{.Void = {}};
            } else {
                stream.pos -= 1;
                var index_33bit = try std.leb.readILEB128(i33, reader);
                if (index_33bit < 0) {
                    return error.InvalidBytecode;
                }
                var index:u32 = @intCast(u32, index_33bit);
                return BlockTypeValue{.TypeIndex = index};
            }
        } else {
            var valtype:Type = valtype_or_err catch unreachable;
            return BlockTypeValue{.Valtype = valtype};
        }
    }

    fn executeWasm(self: *Self, bytecode: []const u8, offset: u32) !void {
        var stream = std.io.fixedBufferStream(bytecode);
        try stream.seekTo(offset);
        var reader = stream.reader();

        while (stream.pos < stream.buffer.len) {
            const instruction: Instruction = @intToEnum(Instruction, try reader.readByte());

            // std.debug.print("found instruction: {}\n", .{instruction});

            switch (instruction) {
                Instruction.Unreachable => {
                    return error.Unreachable;
                },
                Instruction.Noop => {},
                Instruction.Block => {
                    const label_offset = @intCast(u32, stream.pos) - 1;

                    var blocktype = try readBlockType(&stream);
                    var arity:u32 = switch (blocktype) {
                        .Void => 0,
                        .Valtype => 1,
                        .TypeIndex => |index| @intCast(u32, self.types.items[index].getReturns().len),
                    };

                    // std.debug.print("blocktype: {}, arity: {}\n\n", .{blocktype, arity});

                    const continuation = self.label_continuations.get(label_offset) orelse return error.InvalidLabel;
                    try self.stack.pushLabel(arity, continuation);
                },
                Instruction.End => {
                    var returns = std.ArrayList(TypedValue).init(self.allocator);
                    defer returns.deinit();

                    // id 0 means this is the end of a function, otherwise it's the end of a block
                    const label_ptr:*const Label = self.stack.topLabel();
                    if (label_ptr.id != 0) {
                        try returns.ensureTotalCapacity(label_ptr.arity);
                        while (returns.items.len < label_ptr.arity) {
                            try returns.append(try self.stack.popValue());
                        }
                        _ = try self.stack.popLabel();

                        while (returns.items.len > 0) {
                            var item = returns.orderedRemove(returns.items.len - 1);
                            // std.debug.print("push return: {}\n", .{item});
                            try self.stack.pushValue(item);
                        }
                    } else {
                        var frame: *const CallFrame = try self.stack.findCurrentFrame();
                        const returnTypes: []const Type = self.types.items[frame.func.typeIndex].getReturns();

                        try returns.ensureTotalCapacity(returnTypes.len);

                        for (returnTypes) |valtype| {
                            var value = try self.stack.popValue();
                            if (valtype != std.meta.activeTag(value)) {
                                // std.debug.print("valtype: {}, active: {}\n", .{valtype, std.meta.activeTag(value)});
                                return error.TypeMismatch;
                            }

                            try returns.append(value);
                        }

                        var label = try self.stack.popLabel();
                        try self.stack.popFrame();

                        const is_root_function = (self.stack.size() == 0);

                        while (returns.items.len > 0) {
                            var item = returns.orderedRemove(returns.items.len - 1);
                            // std.debug.print("push return: {}\n", .{item});
                            try self.stack.pushValue(item);
                        }

                        // std.debug.print("returning from func call... is root: {}\n", .{is_root_function});
                        if (is_root_function) {
                            return;
                        } else {
                            try stream.seekTo(label.continuation);
                        }
                    }
                },
                Instruction.Branch => {
                    const label_id = try std.leb.readULEB128(u32, reader);
                    try self.branch(&stream, label_id);
                },
                Instruction.Branch_If => {
                    const label_id = try std.leb.readULEB128(u32, reader);
                    const v = try self.stack.popI32();
                    // std.debug.print("branch_if stack value: {}, target id: {}\n", .{v, label_id});
                    if (v != 0) {
                        try self.branch(&stream, label_id);
                    }
                },
                Instruction.Return => {
                    var frame: *const CallFrame = try self.stack.findCurrentFrame();
                    const returnTypes: []const Type = self.types.items[frame.func.typeIndex].getReturns();

                    var returns = std.ArrayList(TypedValue).init(self.allocator);
                    defer returns.deinit();
                    try returns.ensureTotalCapacity(returnTypes.len);

                    while (returns.items.len < returnTypes.len) {
                        var value = try self.stack.popValue();
                        if (std.meta.activeTag(value) != returnTypes[returns.items.len]) {
                            return error.TypeMismatch;
                        }
                        try returns.append(value);
                    }

                    var last_label:Label = undefined;
                    while (true) {
                        var item:*const StackItem = try self.stack.top();
                        switch (item.*) {
                            .Value => { _ = try self.stack.popValue(); },
                            .Label => { last_label = try self.stack.popLabel(); },
                            .Frame => { _ = try self.stack.popFrame(); break; },
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
                Instruction.Call => {
                    var func_index = try self.stack.popI32();
                    // std.debug.print("call function {}\n", .{func_index});
                    const func: *const Function = &self.functions.items[@intCast(usize, func_index)];
                    const functype: *const FunctionType = &self.types.items[func.typeIndex];

                    var frame = CallFrame{
                        .func =  func,
                        .locals = std.ArrayList(TypedValue).init(self.allocator),
                    };

                    const param_types: []const Type = functype.getParams();
                    const return_types: []const Type = functype.getReturns();
                    try frame.locals.ensureTotalCapacity(param_types.len);

                    var param_index = param_types.len;
                    while (param_index > 0) {
                        param_index -= 1;
                        var value = try self.stack.popValue();
                        if (std.meta.activeTag(value) != param_types[param_index]) {
                            return error.TypeMismatch;
                        }
                        try frame.locals.append(value);
                    }

                    const continuation = @intCast(u32, stream.pos);

                    try self.stack.pushFrame(frame);
                    try self.stack.pushLabel(@intCast(u32, return_types.len), continuation);
                    try stream.seekTo(func.bytecodeOffset);
                },
                Instruction.Drop => {
                    _ = try self.stack.popValue();
                },
                Instruction.Select => {
                    var boolean = try self.stack.popValue();
                    var v2 = try self.stack.popValue();
                    var v1 = try self.stack.popValue();

                    if (builtin.mode == .Debug) {
                        if (std.meta.activeTag(boolean) != Type.I32) {
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
                Instruction.Local_Get => {
                    var locals_index = try std.leb.readULEB128(u32, reader);
                    var frame_or_null:?*const CallFrame = try self.stack.findCurrentFrame();
                    if (frame_or_null) |frame| {
                        var v:TypedValue = frame.locals.items[locals_index];
                        try self.stack.pushValue(v);
                    }
                },
                Instruction.Local_Set => {
                    var locals_index = try std.leb.readULEB128(u32, reader);
                    var frame_or_null:?*const CallFrame = try self.stack.findCurrentFrame();
                    if (frame_or_null) |frame| {
                        var v:TypedValue = try self.stack.popValue();
                        frame.locals.items[locals_index] = v;
                    }
                },
                Instruction.Local_Tee => {
                    var locals_index = try std.leb.readULEB128(u32, reader);
                    var frame_or_null:?*const CallFrame = try self.stack.findCurrentFrame();
                    if (frame_or_null) |frame| {
                        var v:TypedValue = try self.stack.topValue();
                        frame.locals.items[locals_index] = v;
                    }
                },
                Instruction.Global_Get => {
                    var global_index = try std.leb.readULEB128(u32, reader);
                    // std.debug.print("read index: {}\n", .{global_index});
                    var global = &self.globals.items[global_index];
                    try self.stack.pushValue(global.value);
                },
                Instruction.Global_Set => {
                    var global_index = try std.leb.readULEB128(u32, reader);
                    var global = &self.globals.items[global_index];
                    if (global.mut == GlobalValue.Mut.Immutable) {
                        return error.AttemptToSetImmutable;
                    }
                    global.value = try self.stack.popValue();
                },
                Instruction.I32_Const => {
                    var v: i32 = try std.leb.readILEB128(i32, reader);
                    try self.stack.pushI32(v);
                },
                Instruction.I32_Eqz => {
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 == 0) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_Eq => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 == v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_NE => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 != v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_LT_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_LT_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_GT_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_GT_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_LE_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_LE_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_GE_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_GE_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_Add => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result = v1 + v2;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_Sub => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var result = v1 - v2;
                    try self.stack.pushI32(result);
                },
                Instruction.I32_Mul => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var value = v1 * v2;
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Div_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var value = try std.math.divTrunc(i32, v1, v2);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Div_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value_unsigned = try std.math.divFloor(u32, v1, v2);
                    var value = @bitCast(i32, value_unsigned);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Rem_S => {
                    var v2: i32 = try self.stack.popI32();
                    var v1: i32 = try self.stack.popI32();
                    var value = @rem(v1, v2);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Rem_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 % v2);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_And => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 & v2);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Or => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 | v2);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Xor => {
                    var v2: u32 = @bitCast(u32, try self.stack.popI32());
                    var v1: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, v1 ^ v2);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Shl => {
                    var shift_unsafe: i32 = try self.stack.popI32();
                    var int: i32 = try self.stack.popI32();
                    var shift = @intCast(u5, shift_unsafe);
                    var value = int << shift;
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Shr_S => {
                    var shift_unsafe: i32 = try self.stack.popI32();
                    var int: i32 = try self.stack.popI32();
                    var shift = @intCast(u5, shift_unsafe);
                    var value = int >> shift;
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Shr_U => {
                    var shift_unsafe: i32 = try self.stack.popI32();
                    var int: u32 = @bitCast(u32, try self.stack.popI32());
                    var shift = @intCast(u5, shift_unsafe);
                    var value = @bitCast(i32, int >> shift);
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Rotl => {
                    var rot: u32 = @bitCast(u32, try self.stack.popI32());
                    var int: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, std.math.rotl(u32, int, rot));
                    try self.stack.pushI32(value);
                },
                Instruction.I32_Rotr => {
                    var rot: u32 = @bitCast(u32, try self.stack.popI32());
                    var int: u32 = @bitCast(u32, try self.stack.popI32());
                    var value = @bitCast(i32, std.math.rotr(u32, int, rot));
                    try self.stack.pushI32(value);
                },
                // else => return error.UnknownInstruction,
            }
        }
    }

    fn branch(self: *Self, stream: *BytecodeBufferStream, label_id: u32) !void {
        const label:*const Label = try self.stack.findLabel(label_id);
        if (label.last_label_index == -1) {
            return error.LabelMismatch; // can't branch to the end of functions - that's the return instruction's job
        }
        const label_stack_id = label.id;
        const continuation = label.continuation;

        // std.debug.print("found label: {}\n", .{label});

        var args = std.ArrayList(TypedValue).init(self.allocator);
        defer args.deinit();
        try args.ensureTotalCapacity(label.arity);

        // std.debug.print("args.len: {}, label.arity: {}\n", .{args.items.len, label});

        while (args.items.len < label.arity) {
            var value = try self.stack.popValue();
            try args.append(value);
        }

        while (true) {
            var topItem = try self.stack.top();
            switch (std.meta.activeTag(topItem.*)) {
                .Value => {
                    _ = try self.stack.popValue();
                },
                .Frame => {
                    return error.InvalidLabel;
                },
                .Label => {
                    const popped_label:Label = try self.stack.popLabel();
                    if (popped_label.id == label_stack_id) {
                        break;
                    }
                }
            }
        }

        while (args.items.len > 0) {
            var value = args.orderedRemove(args.items.len - 1);
            try self.stack.pushValue(value);
        }

        // std.debug.print("branching to continuation: {}\n", .{continuation});
        try stream.seekTo(continuation);
    }
};

const FunctionBuilder = struct {
    const Self = @This();

    instructions: std.ArrayList(u8),

    fn init(allocator: *std.mem.Allocator) Self {
        var self = Self{
            .instructions = std.ArrayList(u8).init(allocator),
        };
        return self;
    }

    fn deinit(self:*Self) void {
        self.instructions.deinit();
    }

    fn add(self: *Self, comptime instruction:Instruction) !void {
        if (isInstructionMultiByte(instruction)) {
            unreachable; // Use one of the other add functions.
        }

        var writer = self.instructions.writer();
        try writer.writeByte(@enumToInt(instruction));
    }

    fn addBlock(self: *Self, comptime blocktype: BlockType, param: anytype) !void {
        var writer = self.instructions.writer();
        try writer.writeByte(@enumToInt(Instruction.Block));

        switch (blocktype) {
            .Void => {
                try writer.writeByte(block_type_void_sentinel_byte);
            },
            .Valtype => {
                if (@TypeOf(param) != Type) {
                    unreachable; // When adding a Valtype block, you must specify which Type it is.
                }
                try writer.writeByte(@enumToInt(param));
            },
            .TypeIndex => {
                var index:i33 = param;
                try std.leb.writeILEB128(writer, index);
            }
        }
    }

    fn addBranch(self: *Self, comptime branch: Instruction, label_index: u32) !void {
        var writer = self.instructions.writer();

        switch (branch) {
            .Branch => {
                try writer.writeByte(@enumToInt(Instruction.Branch));
                try std.leb.writeULEB128(writer, @intCast(u32, label_index));
            },
            .Branch_If => {
                try writer.writeByte(@enumToInt(Instruction.Branch_If));
                try std.leb.writeULEB128(writer, @intCast(u32, label_index));
            },
            else => {
                unreachable; // pass Branch, Branch_If, or Branch_Table
            }
        }
    }

    fn addConstant(self: *Self, comptime T: type, value: T) !void {
        var writer = self.instructions.writer();
        switch (T) {
            i32 => { 
                try writer.writeByte(@enumToInt(Instruction.I32_Const));
                try std.leb.writeILEB128(writer, value); 
            },
            // TODO i64, f32, f64
            else => unreachable,
        }
    }

    fn addVariable(self: *Self, instruction:Instruction, index:u32) !void {
        switch (instruction) {
            .Local_Get => {},
            .Local_Set => {},
            .Local_Tee => {},
            .Global_Get => {},
            .Global_Set => {},
            else => unreachable,
        }

        var writer = self.instructions.writer();
        try writer.writeByte(@enumToInt(instruction));
        try std.leb.writeULEB128(writer, index);
    }
};

const ModuleBuilder = struct {
    const Self = @This();

    const WasmFunction = struct {
        exportName: std.ArrayList(u8),
        ftype: FunctionType,
        locals: std.ArrayList(Type),
        instructions: std.ArrayList(u8),
    };

    const WasmGlobal = struct {
        exportName: std.ArrayList(u8),
        type: Type,
        mut: GlobalValue.Mut,
        initInstructions: std.ArrayList(u8),
    };

    allocator: *std.mem.Allocator,
    functions: std.ArrayList(WasmFunction),
    globals: std.ArrayList(WasmGlobal),
    wasm: std.ArrayList(u8),
    needsRebuild: bool = true,

    fn init(allocator: *std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .functions = std.ArrayList(WasmFunction).init(allocator),
            .globals = std.ArrayList(WasmGlobal).init(allocator),
            .wasm = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(self: *Self) void {
        for (self.functions.items) |*func| {
            func.exportName.deinit();
            func.ftype.types.deinit();
            func.locals.deinit();
            func.instructions.deinit();
        }
        self.functions.deinit();

        for (self.globals.items) |*global| {
            global.exportName.deinit();
            global.initInstructions.deinit();
        }
        self.globals.deinit();

        self.wasm.deinit();
    }

    fn addFunc(self: *Self, exportName: ?[]const u8, params: []const Type, returns: []const Type, locals: []const Type, instructions: []const u8) !void {
        var f = WasmFunction{
            .exportName = std.ArrayList(u8).init(self.allocator),
            .ftype = FunctionType{
                .types = std.ArrayList(Type).init(self.allocator),
                .numParams = @intCast(u32, params.len),
            },
            .locals = std.ArrayList(Type).init(self.allocator),
            .instructions = std.ArrayList(u8).init(self.allocator),
        };
        errdefer f.exportName.deinit();
        errdefer f.ftype.types.deinit();
        errdefer f.locals.deinit();
        errdefer f.instructions.deinit();

        if (exportName) |name| {
            try f.exportName.appendSlice(name);
        }
        try f.ftype.types.appendSlice(params);
        try f.ftype.types.appendSlice(returns);
        try f.locals.appendSlice(locals);
        try f.instructions.appendSlice(instructions);

        try self.functions.append(f);

        self.needsRebuild = true;
    }

    fn addGlobal(self: *Self, exportName: ?[]const u8, valtype: Type, mut: GlobalValue.Mut, initOpts:GlobalValueInitOptions) !void {
        var g = WasmGlobal{
            .exportName = std.ArrayList(u8).init(self.allocator),
            .type = valtype,
            .mut = mut,
            .initInstructions = std.ArrayList(u8).init(self.allocator),
        };
        errdefer g.exportName.deinit();
        errdefer g.initInstructions.deinit();

        if (exportName) |name| {
            try g.exportName.appendSlice(name);
        }

        switch (initOpts) {
            .Value => |v| {
                var writer = g.initInstructions.writer();
                try writeTypedValue(v, writer);
                try writer.writeByte(@enumToInt(Instruction.End));
            },
        }

        try self.globals.append(g);

        self.needsRebuild = true;
    }

    fn build(self: *Self) !void {
        self.wasm.clearRetainingCapacity();

        // dedupe function types and sort for quick lookup
        const FunctionTypeSetType = std.HashMap(*FunctionType, *FunctionType, FunctionTypeContext, std.hash_map.default_max_load_percentage);
        var functionTypeSet = FunctionTypeSetType.init(self.allocator);
        defer functionTypeSet.deinit();

        // std.debug.print("self.functions.items: {s}\n", .{self.functions.items});
        for (self.functions.items) |*func| {
            _ = try functionTypeSet.getOrPut(&func.ftype);
        }

        var functionTypesSorted = std.ArrayList(*FunctionType).init(self.allocator);
        defer functionTypesSorted.deinit();
        try functionTypesSorted.ensureTotalCapacity(functionTypeSet.count());
        {
            var iter = functionTypeSet.iterator();
            var entry = iter.next();
            while (entry != null) {
                if (entry) |e| {
                    try functionTypesSorted.append(e.key_ptr.*);
                    entry = iter.next();
                }
            }
        }
        std.sort.sort(*FunctionType, functionTypesSorted.items, FunctionTypeContext{}, FunctionTypeContext.less);

        // Serialize header and sections

        const header = [_]u8{
            0x00, 0x61, 0x73, 0x6D,
            0x01, 0x00, 0x00, 0x00,
        };

        try self.wasm.appendSlice(&header);

        var sectionBytes = std.ArrayList(u8).init(self.allocator);
        defer sectionBytes.deinit();
        try sectionBytes.ensureTotalCapacity(1024 * 4);

        var scratchBuffer = std.ArrayList(u8).init(self.allocator);
        defer scratchBuffer.deinit();
        try scratchBuffer.ensureTotalCapacity(1024);

        const sectionsToSerialize = [_]Section{ .FunctionType, .Function, .Global, .Export, .Code };
        for (sectionsToSerialize) |section| {
            sectionBytes.clearRetainingCapacity();
            var writer = sectionBytes.writer();
            switch (section) {
                .FunctionType => {
                    try std.leb.writeULEB128(writer, @intCast(u32, functionTypesSorted.items.len));
                    for (functionTypesSorted.items) |funcType| {
                        try writer.writeByte(function_type_sentinel_byte);

                        var params = funcType.getParams();
                        var returns = funcType.getReturns();

                        try std.leb.writeULEB128(writer,  @intCast(u32, params.len));
                        for (params) |v| {
                            try writer.writeByte(@enumToInt(v));
                        }
                        try std.leb.writeULEB128(writer,  @intCast(u32, returns.len));
                        for (returns) |v| {
                            try writer.writeByte(@enumToInt(v));
                        }
                    }
                },
                .Function => {
                    try std.leb.writeULEB128(writer,  @intCast(u32, self.functions.items.len));
                    for (self.functions.items) |*func| {
                        var context = FunctionTypeContext{};
                        var index: ?usize = std.sort.binarySearch(*FunctionType, &func.ftype, functionTypesSorted.items, context, FunctionTypeContext.order);
                        try std.leb.writeULEB128(writer,  @intCast(u32, index.?));
                    }
                },
                .Global => {
                    try std.leb.writeULEB128(writer,  @intCast(u32, self.globals.items.len));
                    for (self.globals.items) |global| {
                        try writer.writeByte(@enumToInt(global.mut));
                        try writer.writeByte(@enumToInt(global.type));
                        _ = try writer.write(global.initInstructions.items);
                    }
                },
                .Export => {
                    var num_exports:u32 = 0;
                    for (self.functions.items) |func| {
                        if (func.exportName.items.len > 0) {
                            num_exports += 1;
                        }
                    }
                    for (self.globals.items) |global| {
                        if (global.exportName.items.len > 0) {
                            num_exports += 1;
                        }
                    }

                    try std.leb.writeULEB128(writer, @intCast(u32, num_exports));

                    for (self.functions.items) |func, i| {
                        if (func.exportName.items.len > 0) {
                            try std.leb.writeULEB128(writer,  @intCast(u32, func.exportName.items.len));
                            _ = try writer.write(func.exportName.items);
                            try writer.writeByte(@enumToInt(ExportType.Function));
                            try std.leb.writeULEB128(writer,  @intCast(u32, i));
                        }
                    }
                    for (self.globals.items) |global, i| {
                        if (global.exportName.items.len > 0) {
                            try std.leb.writeULEB128(writer,  @intCast(u32, global.exportName.items.len));
                            _ = try writer.write(global.exportName.items);
                            try writer.writeByte(@enumToInt(ExportType.Global));
                            try std.leb.writeULEB128(writer,  @intCast(u32, i));
                        }
                    }
                },
                .Code => {
                    try std.leb.writeULEB128(writer,  @intCast(u32, self.functions.items.len));
                    for (self.functions.items) |func| {
                        var scratchWriter = scratchBuffer.writer();
                        defer scratchBuffer.clearRetainingCapacity();

                        try std.leb.writeULEB128(scratchWriter,  @intCast(u32, func.locals.items.len));
                        for (func.locals.items) |local| {
                            try scratchWriter.writeByte(@enumToInt(local));
                        }
                        _ = try scratchWriter.write(func.instructions.items);
                        // TODO should the client supply an end instruction instead?
                        try scratchWriter.writeByte(@enumToInt(Instruction.End));

                        try std.leb.writeULEB128(writer, @intCast(u32, scratchBuffer.items.len));
                        try sectionBytes.appendSlice(scratchBuffer.items);
                    }
                },
                else => { 
                    unreachable;
                }
            }

            if (sectionBytes.items.len > 0) {
                var wasmWriter = self.wasm.writer();
                try wasmWriter.writeByte(@enumToInt(section));
                try std.leb.writeULEB128(wasmWriter, @intCast(u32, sectionBytes.items.len));
                _ = try wasmWriter.write(sectionBytes.items);
            }
        }
    }

    fn getWasm(self: *Self) ![]const u8 {
        if (self.needsRebuild) {
            try self.build();
        }

        return self.wasm.items;
    }
};

fn writeTypedValue(value:TypedValue, writer: anytype) !void {
    switch (value) {
        .I32 => |v| {
            try writer.writeByte(@enumToInt(Instruction.I32_Const));
            try std.leb.writeILEB128(writer, @intCast(i32, v));
        },
        else => unreachable,
        // .I64 => |v| {
        //     try writer.writeByte(@enumToInt(Instruction.I64_Const));
        //     try writer.writeIntBig(i64, v);
        // },
        // .F32 => |v| {
        //     try writer.writeByte(@enumToInt(Instruction.F32_Const));
        //     try writer.writeIntBig(f32, v);
        // },
        // .F64 => |v| {
        //     try writer.writeByte(@enumToInt(Instruction.F64_Const));
        //     try writer.writeIntBig(f64, v);
        // },
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Tests

const TestFunction = struct{
    bytecode: []const u8,
    exportName: ?[]const u8 = null,
    params: ?[]Type = null,
    locals: ?[]Type = null,
    returns: ?[]Type = null,
};

const TestGlobal = struct {
    exportName: ?[]const u8,
    initValue: TypedValue,
    mut: GlobalValue.Mut,
};

const TestOptions = struct {
    startFunctionIndex:u32 = 0,
    startFunctionParams: ?[]TypedValue = null,
    functions: [] const TestFunction,
    globals: ?[]const TestGlobal = null,
};

fn testCallFunc(options:TestOptions, expectedReturns:?[]TypedValue) !void {
    var builder = ModuleBuilder.init(std.testing.allocator);
    defer builder.deinit();

    for (options.functions) |func|
    {
        const params = func.params orelse &[_]Type{};
        const locals = func.locals orelse &[_]Type{};
        const returns = func.returns orelse &[_]Type{};

        try builder.addFunc(func.exportName, params, returns, locals, func.bytecode);
    }

    if (options.globals) |globals| {
        for (globals) |global| {
            var valtype = std.meta.activeTag(global.initValue);
            var initOpts = GlobalValueInitOptions{
                .Value = global.initValue,
            };

            try builder.addGlobal(global.exportName, valtype, global.mut, initOpts);
        }
    }

    const wasm = try builder.getWasm();
    var vm = try VmState.parseWasm(wasm, .UseExisting, std.testing.allocator);
    defer vm.deinit();

    const params = options.startFunctionParams orelse &[_]TypedValue{};

    var returns = std.ArrayList(TypedValue).init(std.testing.allocator);
    defer returns.deinit();

    if (expectedReturns) |expected| {
        try returns.resize(expected.len);
    }

    var name = options.functions[options.startFunctionIndex].exportName orelse "";
    try vm.callFunc(name, params, returns.items);

    if (expectedReturns) |expected|
    {
        for (expected) |expectedValue, i| {
            if (std.meta.activeTag(expectedValue) == Type.I32) {
                var result_u32 = @bitCast(u32, returns.items[i].I32);
                var expected_u32 = @bitCast(u32, expectedValue.I32);
                if (result_u32 != expected_u32) {
                    std.debug.print("expected: 0x{X}, result: 0x{X}\n", .{ expected_u32, result_u32 });
                }                
            }
            try std.testing.expect(std.meta.eql(expectedValue, returns.items[i]));
        }
    }
}

fn testCallFuncI32ParamReturn(bytecode: []const u8, param:i32, expected:i32) !void {
    var types = [_]Type{.I32};
    var functions = [_]TestFunction{
        .{
            .bytecode = bytecode,
            .exportName = "testFunc",
            .params = &types,
            .locals = &types,
            .returns = &types,
        },
    };
    var params = [_]TypedValue{
        .{.I32 = param}
    };
    var opts = TestOptions{
        .startFunctionParams = &params,
        .functions = &functions,
    };
    var expectedReturns = [_]TypedValue{.{.I32 = expected}};
    try testCallFunc(opts, &expectedReturns);
}

fn testCallFuncI32Return(bytecode: []const u8, expected:i32) !void {
    var types = [_]Type{.I32};
    var functions = [_]TestFunction{
        .{
            .bytecode = bytecode,
            .exportName = "testFunc",
            .returns = &types,
        },
    };
    var opts = TestOptions{
        .functions = &functions,
    };
    var expectedReturns = [_]TypedValue{.{.I32 = expected}};
    try testCallFunc(opts, &expectedReturns);
}

fn testCallFuncU32Return(bytecode: []const u8, expected:u32) !void {
    try testCallFuncI32Return(bytecode, @bitCast(i32, expected));
}

fn testCallFuncSimple(bytecode: []const u8) !void {
    var opts = TestOptions{
        .functions = &[_]TestFunction{
            .{
                .bytecode = bytecode,
                .exportName = "testFunc",
            },
        },
    };

    try testCallFunc(opts, null);
}

fn printBytecode(label: []const u8, bytecode: []const u8) void {
    std.debug.print("\n\n{s}: \n\t", .{label});
    var tab:u32 = 0;
    for (bytecode) |byte| {
        if (tab == 4) {
            std.debug.print("\n\t", .{});
            tab = 0;
        }
        tab += 1;
        std.debug.print("0x{X:2} ", .{byte});
    }
    std.debug.print("\n", .{});
}

test "module builder" {
    var builder = ModuleBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addGlobal("glb1", Type.I32, GlobalValue.Mut.Immutable, GlobalValueInitOptions{.Value = TypedValue{.I32=0x88}});
    try builder.addFunc("abcd", &[_]Type{.I64}, &[_]Type{.I32}, &[_]Type{ .I32, .I64 }, &[_]u8{ 0x01, 0x01, 0x01, 0x01 });
    var wasm = try builder.getWasm();

    var expected = std.ArrayList(u8).init(std.testing.allocator);
    defer expected.deinit();
    try expected.ensureTotalCapacity(1024);

    {
        var writer = expected.writer();

        _ = try writer.write(&[_]u8{0x00, 0x61, 0x73, 0x6D});
        try writer.writeIntLittle(u32, 1);
        try writer.writeByte(@enumToInt(Section.FunctionType));
        try std.leb.writeULEB128(writer, @intCast(u32, 0x6)); // section size
        try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num types
        try writer.writeByte(function_type_sentinel_byte);
        try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num params
        try writer.writeByte(@enumToInt(Type.I64));
        try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num returns
        try writer.writeByte(@enumToInt(Type.I32));
        try writer.writeByte(@enumToInt(Section.Function));
        try std.leb.writeULEB128(writer, @intCast(u32, 0x2)); // section size
        try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num functions
        try std.leb.writeULEB128(writer, @intCast(u32, 0x0)); // index to types
        try writer.writeByte(@enumToInt(Section.Global));
        try std.leb.writeULEB128(writer, @intCast(u32, 0x7)); // section size
        try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num globals
        try writer.writeByte(@enumToInt(GlobalValue.Mut.Immutable));
        try writer.writeByte(@enumToInt(Type.I32));
        try writer.writeByte(@enumToInt(Instruction.I32_Const));
        try std.leb.writeILEB128(writer, @intCast(i32, 0x88));
        try writer.writeByte(@enumToInt(Instruction.End));
        try writer.writeByte(@enumToInt(Section.Export));
        try std.leb.writeULEB128(writer, @intCast(u32, 0xF)); // section size
        try std.leb.writeULEB128(writer, @intCast(u32, 0x2)); // num exports
        try std.leb.writeULEB128(writer, @intCast(u32, 0x4)); // size of export name (1)
        _ = try writer.write("abcd");
        try writer.writeByte(@enumToInt(ExportType.Function));
        try std.leb.writeULEB128(writer, @intCast(u32, 0x0)); // index of export
        try std.leb.writeULEB128(writer, @intCast(u32, 0x4)); // size of export name (2)
        _ = try writer.write("glb1");
        try writer.writeByte(@enumToInt(ExportType.Global));
        try std.leb.writeULEB128(writer, @intCast(u32, 0x0)); // index of export
        try writer.writeByte(@enumToInt(Section.Code));
        try std.leb.writeULEB128(writer, @intCast(u32, 0xA)); // section size
        try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num codes
        try std.leb.writeULEB128(writer, @intCast(u32, 0x8)); // code size
        try std.leb.writeULEB128(writer, @intCast(u32, 0x2)); // num locals
        try writer.writeByte(@enumToInt(Type.I32));
        try writer.writeByte(@enumToInt(Type.I64));
        try writer.writeByte(@enumToInt(Instruction.Noop));
        try writer.writeByte(@enumToInt(Instruction.Noop));
        try writer.writeByte(@enumToInt(Instruction.Noop));
        try writer.writeByte(@enumToInt(Instruction.Noop));
        try writer.writeByte(@enumToInt(Instruction.End));
    }

    const areEqual = std.mem.eql(u8, wasm, expected.items);

    if (!areEqual) {
        printBytecode("expected", expected.items);
        printBytecode("actual", wasm);
    }

    try std.testing.expect(areEqual);
}

test "unreachable" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.add(.Unreachable);

    var didCatchError:bool = false;
    var didCatchCorrectError:bool = false;
    testCallFuncSimple(builder.instructions.items) catch |e| {
        didCatchError = true;
        didCatchCorrectError = (e == VMError.Unreachable);
    };

    try std.testing.expect(didCatchError);
    try std.testing.expect(didCatchCorrectError);
}

test "noop" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);
    try builder.add(.Noop);

    try testCallFuncSimple(builder.instructions.items);
}

test "block void" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addBlock(.Void, .{});
    try builder.add(.End);
    try testCallFuncSimple(builder.instructions.items);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(.Void, .{});
    try builder.addConstant(i32, 0x1337);
    try builder.add(.End);
    var didCatchError = false;
    var didCatchCorrectError = false;
    testCallFuncSimple(builder.instructions.items) catch |e| {
        didCatchError = true;
        didCatchCorrectError = (e == VMError.TypeMismatch);
    };
    try std.testing.expect(didCatchError);
}

test "block valtypes" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addBlock(.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.add(.End);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(.Valtype, Type.I32);
    try builder.add(.End);
    var didCatchError = false;
    var didCatchCorrectError = false;
    testCallFuncSimple(builder.instructions.items) catch |e| {
        didCatchError = true;
        didCatchCorrectError = (e == VMError.TypeMismatch);
    };
    try std.testing.expect(didCatchError);
}

// test "block typeidx" {
    
// }

test "branch" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addBlock(BlockType.Void, .{});
    try builder.addBranch(Instruction.Branch, 0);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try testCallFuncSimple(builder.instructions.items);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.addBranch(Instruction.Branch, 0);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.addBranch(Instruction.Branch, 2);
    try builder.add(Instruction.End);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try builder.add(Instruction.Drop);
    try builder.addConstant(i32, 0xDEAD);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.addBranch(Instruction.Branch, 1);
    try builder.add(Instruction.End);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try builder.add(Instruction.Drop);
    try builder.addConstant(i32, 0xDEAD);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0xDEAD);
}

test "branch_if" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addBlock(BlockType.Void, .{});
    try builder.addConstant(i32, 1);
    try builder.addBranch(Instruction.Branch_If, 0);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try testCallFuncSimple(builder.instructions.items);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0x1);
    try builder.addBranch(Instruction.Branch_If, 0);
    try builder.add(Instruction.Drop);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0x0);
    try builder.addBranch(Instruction.Branch_If, 0);
    try builder.add(Instruction.Drop);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0xBEEF);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0x1);
    try builder.addBranch(Instruction.Branch_If, 2);
    try builder.add(Instruction.End);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try builder.add(Instruction.Drop);
    try builder.addConstant(i32, 0xDEAD);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);

    builder.instructions.clearRetainingCapacity();
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0x1);
    try builder.addBranch(Instruction.Branch_If, 1);
    try builder.add(Instruction.End);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try builder.add(Instruction.Drop);
    try builder.addConstant(i32, 0xDEAD);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0xDEAD);
}

test "return" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    // factorial
    // fn f(v:u32) u32 {
    //     if (v == 1) {
    //          return 0x1337;
    //     } else if (v == 2) {
    //          return 0xBEEF;
    //     } else {
    //          return 0x12345647;
    //     }
    // }

    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addConstant(i32, 0x1337);
    try builder.add(Instruction.Return);
    try builder.add(Instruction.End);
    try builder.addConstant(i32, 0xDEAD);
    try builder.add(Instruction.End);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.End);
    try builder.addConstant(i32, 0xFACE);
    try builder.add(Instruction.End);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);
}

test "call and return" {
    var builder0 = FunctionBuilder.init(std.testing.allocator);
    var builder1 = FunctionBuilder.init(std.testing.allocator);
    var builder2 = FunctionBuilder.init(std.testing.allocator);
    defer builder0.deinit();
    defer builder1.deinit();
    defer builder2.deinit();

    try builder0.addVariable(Instruction.Local_Get, 0);
    try builder0.addConstant(i32, 0x421);
    try builder0.add(Instruction.I32_Add); // 0x42 + 0x421 = 0x463
    try builder0.addConstant(i32, 0x01);
    try builder0.add(Instruction.Call);

    try builder1.addVariable(Instruction.Local_Get, 0);
    try builder1.addConstant(i32, 0x02);
    try builder1.add(Instruction.I32_Mul); // 0x463 * 2 = 0x8C6
    try builder1.addConstant(i32, 0x02);
    try builder1.add(Instruction.Call);
    try builder0.add(Instruction.Return);

    try builder2.addVariable(Instruction.Local_Get, 0);
    try builder2.addConstant(i32, 0xBEEF);
    try builder2.add(Instruction.I32_Add); // 0x8C6 + 0xBEEF = 0xC7B5
    try builder2.add(Instruction.Return);

    var types = [_]Type{.I32};
    var functions = [_]TestFunction{
        .{
            .exportName = "testFunc",
            .bytecode = builder0.instructions.items,
            .params = &types,
            .locals = &types,
            .returns = &types,
        },
        .{
            .bytecode = builder1.instructions.items,
            .params = &types,
            .locals = &types,
            .returns = &types,
        },
        .{
            .bytecode = builder2.instructions.items,
            .params = &types,
            .locals = &types,
            .returns = &types,
        },
    };
    var params = [_]TypedValue{.{.I32 = 0x42}};
    var opts = TestOptions{
        .functions = &functions,
        .startFunctionParams = &params,
    };
    var expected = [_]TypedValue{.{.I32 = 0xC7B5}};

    try testCallFunc(opts, &expected);
}

test "call recursive" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    // factorial
    // fn f(v:u32) u32 {
    //     if (v == 1) {
    //         return 1;
    //     } else {
    //         var vv = f(v - 1);
    //         return v * vv;
    //     }
    // }

    try builder.addBlock(BlockType.Valtype, Type.I32);
    try builder.addVariable(Instruction.Local_Get, 0);
    try builder.addVariable(Instruction.Local_Get, 0);
    try builder.addConstant(i32, 1);
    try builder.add(Instruction.I32_Eq);
    try builder.addBranch(Instruction.Branch_If, 0); // return v if 
    try builder.addConstant(i32, 1);
    try builder.add(Instruction.I32_Sub);
    try builder.addConstant(i32, 0); // call func at index 0 (recursion)
    try builder.add(Instruction.Call);
    try builder.addVariable(Instruction.Local_Get, 0);
    try builder.add(Instruction.I32_Mul);
    try builder.add(Instruction.End);
    try testCallFuncI32ParamReturn(builder.instructions.items, 5, 120); // 5! == 120
}

test "drop" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0xBEEF);
    try builder.add(Instruction.Drop);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);
}

test "select" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0xBEEF);
    try builder.addConstant(i32, 0xFF); //nonzero should pick val1
    try builder.add(Instruction.Select);
    try testCallFuncI32Return(builder.instructions.items, 0x1337);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0xBEEF);
    try builder.addConstant(i32, 0x0); //zero should pick val2
    try builder.add(Instruction.Select);
    try testCallFuncI32Return(builder.instructions.items, 0xBEEF);
}

test "local_get" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addVariable(Instruction.Local_Get, 0);
    try testCallFuncI32ParamReturn(builder.instructions.items, 0x1337, 0x1337);
}

test "local_set" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addConstant(i32, 0x1337);
    try builder.addConstant(i32, 0x1336);
    try builder.addConstant(i32, 0x1335);
    try builder.addVariable(Instruction.Local_Set, 0); // pop stack values and set in local
    try builder.addVariable(Instruction.Local_Set, 0);
    try builder.addVariable(Instruction.Local_Set, 0);
    try builder.addVariable(Instruction.Local_Get, 0); // push local value onto stack, should be 1337 since it was the first pushed

    var types = [_]Type{.I32};
    var emptyTypes = [_]Type{};
    var params = [_]TypedValue{};
    var opts = TestOptions{
        .startFunctionParams = &params,
        .functions = &[_]TestFunction{
            .{
                .exportName = "testFunc",
                .bytecode = builder.instructions.items,
                .params = &emptyTypes,
                .locals = &types,
                .returns = &types,
            }
        },
    };
    var expected = [_]TypedValue{.{.I32 = 0x1337}};

    try testCallFunc(opts, &expected);
}

test "local_tee" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addConstant(i32, 0x1337);
    try builder.addVariable(Instruction.Local_Tee, 0); // put value in locals but also leave it on the stack
    try builder.addVariable(Instruction.Local_Get, 0); // push the same value back onto the stack
    try builder.add(Instruction.I32_Add);

    var types = [_]Type{.I32};
    var emptyTypes = [_]Type{};
    var params = [_]TypedValue{};
    var opts = TestOptions{
        .startFunctionParams = &params,
        .functions = &[_]TestFunction{
            .{
                .exportName = "testFunc",
                .bytecode = builder.instructions.items,
                .params = &emptyTypes,
                .locals = &types,
                .returns = &types,
            }
        },
    };
    var expected = [_]TypedValue{.{.I32 = 0x266E}};

    try testCallFunc(opts, &expected);
}

test "global_get" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addVariable(Instruction.Global_Get, 0x0);

    var returns = [_]Type{.I32};
    var functions = [_]TestFunction{
        .{
            .exportName = "testFunc",
            .bytecode = builder.instructions.items,
            .returns = &returns,
        }
    };
    var globals = [_]TestGlobal {
        .{
            .exportName = "abcd",
            .initValue = TypedValue{.I32 = 0x1337},
            .mut = GlobalValue.Mut.Immutable,
        },
    };
    var options = TestOptions{
        .functions = &functions,
        .globals = &globals,
    };
    var expected = [_]TypedValue{.{.I32 = 0x1337}};
    try testCallFunc(options, &expected);
}

test "global_set" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addConstant(i32, 0x1337);
    try builder.addVariable(Instruction.Global_Set, 0);
    try builder.addVariable(Instruction.Global_Get, 0);

    var returns = [_]Type{.I32};
    var globals = [_]TestGlobal {
        .{
            .exportName = null,
            .initValue = TypedValue{.I32 = 0x0},
            .mut = GlobalValue.Mut.Mutable,
        },
    };
    var functions = &[_]TestFunction{
        .{
            .exportName = "testFunc",
            .bytecode = builder.instructions.items,
            .returns = &returns,
        }
    };
    var options = TestOptions{
        .functions = functions,
        .globals = &globals,
    };
    var expected = [_]TypedValue{.{.I32 = 0x1337}};

    try testCallFunc(options, &expected);

    globals[0].mut = GlobalValue.Mut.Immutable;
    var didCatchError = false;
    var didCatchCorrectError = false;
    testCallFunc(options, &expected) catch |err| {
        didCatchError = true;
        didCatchCorrectError = (err == VMError.AttemptToSetImmutable);
    };

    try std.testing.expect(didCatchError);
    try std.testing.expect(didCatchCorrectError);
}

test "i32_eqz" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0);
    try builder.add(Instruction.I32_Eqz);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 1);
    try builder.add(Instruction.I32_Eqz);
    try testCallFuncI32Return(builder.instructions.items, 0x0);
}

test "i32_eq" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0);
    try builder.addConstant(i32, 0);
    try builder.add(Instruction.I32_Eq);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0);
    try builder.addConstant(i32, -1);
    try builder.add(Instruction.I32_Eq);
    try testCallFuncI32Return(builder.instructions.items, 0x0);
}

test "i32_ne" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0);
    try builder.addConstant(i32, 0);
    try builder.add(Instruction.I32_NE);
    try testCallFuncI32Return(builder.instructions.items, 0x0);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0);
    try builder.addConstant(i32, -1);
    try builder.add(Instruction.I32_NE);
    try testCallFuncI32Return(builder.instructions.items, 0x1);
}

test "i32_lt_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_LT_S);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_LT_S);
    try testCallFuncI32Return(builder.instructions.items, 0x0);
}

test "i32_lt_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600); // 0xFFFFFA00 when unsigned
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_LT_U);
    try testCallFuncI32Return(builder.instructions.items, 0x0);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_LT_U);
    try testCallFuncI32Return(builder.instructions.items, 0x1);
}

test "i32_gt_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_GT_S);
    try testCallFuncI32Return(builder.instructions.items, 0x0);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_GT_S);
    try testCallFuncI32Return(builder.instructions.items, 0x1);
}

test "i32_gt_u" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600); // 0xFFFFFA00 when unsigned
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_GT_U);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_GT_U);
    try testCallFuncI32Return(builder.instructions.items, 0x0);
}

test "i32_le_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_LE_S);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_LE_S);
    try testCallFuncI32Return(builder.instructions.items, 0x0);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_LE_S);
    try testCallFuncI32Return(builder.instructions.items, 0x1);
}

test "i32_le_u" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_LE_U);
    try testCallFuncI32Return(builder.instructions.items, 0x0);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_LE_U);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_LE_U);
    try testCallFuncI32Return(builder.instructions.items, 0x1);
}

test "i32_ge_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_GE_S);
    try testCallFuncI32Return(builder.instructions.items, 0x0);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_GE_S);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_GE_S);
    try testCallFuncI32Return(builder.instructions.items, 0x1);
}

test "i32_ge_u" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x800);
    try builder.add(Instruction.I32_GE_U);
    try testCallFuncI32Return(builder.instructions.items, 0x1);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, 0x800);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_GE_U);
    try testCallFuncI32Return(builder.instructions.items, 0x0);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, -0x600);
    try builder.add(Instruction.I32_GE_U);
    try testCallFuncI32Return(builder.instructions.items, 0x1);
}

test "i32_add" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0x100001);
    try builder.addConstant(i32, 0x000201);
    try builder.add(Instruction.I32_Add);
    try testCallFuncI32Return(builder.instructions.items, 0x100202);
}

test "i32_sub" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0x100001);
    try builder.addConstant(i32, 0x000201);
    try builder.add(Instruction.I32_Sub);
    try testCallFuncI32Return(builder.instructions.items, 0xFFE00);
}

test "i32_mul" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0x200);
    try builder.addConstant(i32, 0x300);
    try builder.add(Instruction.I32_Mul);
    try testCallFuncI32Return(builder.instructions.items, 0x60000);
}

test "i32_div_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x200);
    try builder.add(Instruction.I32_Div_S);
    var expected:i32 = -3;
    try testCallFuncU32Return(builder.instructions.items, @bitCast(u32, expected));
}

test "i32_div_u" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x600); // 0xFFFFFA00 unsigned
    try builder.addConstant(i32, 0x200);
    try builder.add(Instruction.I32_Div_U);
    try testCallFuncU32Return(builder.instructions.items, 0x7FFFFD);
}

test "i32_rem_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x666);
    try builder.addConstant(i32, 0x200);
    try builder.add(Instruction.I32_Rem_S);
    try testCallFuncI32Return(builder.instructions.items, -0x66);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, -0x600);
    try builder.addConstant(i32, 0x200);
    try builder.add(Instruction.I32_Rem_S);
    try testCallFuncI32Return(builder.instructions.items, 0);
}

test "i32_rem_u" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x666); // 0xFFFFF99A unsigned
    try builder.addConstant(i32, 0x200);
    try builder.add(Instruction.I32_Rem_U);
    try testCallFuncI32Return(builder.instructions.items, 0x19A);

    builder.instructions.clearRetainingCapacity();
    try builder.addConstant(i32, -0x800);
    try builder.addConstant(i32, 0x200);
    try builder.add(Instruction.I32_Rem_U);
    try testCallFuncI32Return(builder.instructions.items, 0);
}

test "i32_and" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0x0FFFFFFF);
    try builder.addConstant(i32, 0x01223344);
    try builder.add(Instruction.I32_And);
    try testCallFuncI32Return(builder.instructions.items, 0x01223344);
}

test "i32_or" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0x0F00FF00);
    try builder.addConstant(i32, 0x01223344);
    try builder.add(Instruction.I32_Or);
    try testCallFuncI32Return(builder.instructions.items, 0x0F22FF44);
}

test "i32_xor" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, 0x0F0F0F0F);
    try builder.addConstant(i32, 0x70F00F0F);
    try builder.add(Instruction.I32_Xor);
    try testCallFuncI32Return(builder.instructions.items, 0x7FFF0000);
}

test "i32_shl" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
    try builder.addConstant(i32, 0x2);
    try builder.add(Instruction.I32_Shl);
    try testCallFuncU32Return(builder.instructions.items, 0x40404);
}

test "i32_shr_s" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
    try builder.addConstant(i32, 0x1);
    try builder.add(Instruction.I32_Shr_S);
    try testCallFuncU32Return(builder.instructions.items, 0xC0008080);
}

test "i32_shr_u" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
    try builder.addConstant(i32, 0x1);
    try builder.add(Instruction.I32_Shr_U);
    try testCallFuncU32Return(builder.instructions.items, 0x40008080);
}

test "i32_rotl" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
    try builder.addConstant(i32, 0x2);
    try builder.add(Instruction.I32_Rotl);
    try testCallFuncU32Return(builder.instructions.items, 0x00040406);
}

test "i32_rotr" {
    var builder = FunctionBuilder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
    try builder.addConstant(i32, 0x2);
    try builder.add(Instruction.I32_Rotr);
    try testCallFuncU32Return(builder.instructions.items, 0x60004040);
}
