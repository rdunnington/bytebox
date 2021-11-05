const std = @import("std");

const VmParseError = error{
    InvalidMagicSignature,
    UnsupportedWasmVersion,
    InvalidBytecode,
    InvalidExport,
};

const VMError = error{
    Unreachable,
    IncompleteInstruction,
    UnknownInstruction,
    TypeMismatch,
    UnknownExport,
};

const Instruction = enum(u8) {
    Unreachable = 0x00,
    Noop = 0x01,
    End = 0x0B,
    Local_Get = 0x20,
    Local_Set = 0x21,
    Local_Tee = 0x22,
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

const Type = enum(u8) {
    Void = 0x00,
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
    // FuncRef = 0x70,
    // ExternRef = 0x6F,
};

const TypedValue = union(Type) {
    Void: void,
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
};

const I32ToU32 = union {
    I32: i32,
    U32: u32,
};

const Stack = struct {
    const Self = @This();

    fn init(allocator: *std.mem.Allocator) Self {
        return Self{
            .stack = std.ArrayList(TypedValue).init(allocator),
        };
    }

    fn deinit(self: *Self) void {
        self.stack.deinit();
    }

    fn top(self: *Self) !TypedValue {
        if (self.stack.items.len > 0) {
            return self.stack.items[self.stack.items.len - 1];
        }
        return error.OutOfBounds;        
    }

    fn pop(self: *Self) !TypedValue {
        if (self.stack.items.len > 0) {
            return self.stack.orderedRemove(self.stack.items.len - 1);
        }
        return error.OutOfBounds;
    }

    fn push(self: *Self, v: TypedValue) !void {
        try self.stack.append(v);
    }

    fn pop_i32(self: *Self) !i32 {
        var typed: TypedValue = try self.pop();
        switch (typed) {
            Type.I32 => |value| return value,
            else => return error.TypeMismatch,
        }
    }

    fn push_i32(self: *Self, v: i32) !void {
        var typed = TypedValue{ .I32 = v };
        try self.push(typed);
    }

    fn size(self: *Self) usize {
        return self.stack.items.len;
    }

    stack: std.ArrayList(TypedValue),
};

const Section = enum(u8) { Custom, FunctionType, Import, Function, Table, Memory, Global, Export, Start, Element, Code, Data, DataCount };

const function_type_sentinel_byte: u8 = 0x60;

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

    const StackFrame = struct {
        func: *const Function,
        stackBaseIndex: u32,
        locals: []TypedValue,
    };

    allocator: *std.mem.Allocator,
    bytecode: []const u8,
    bytecode_mem_usage: std.ArrayList(u8),
    types: std.ArrayList(FunctionType),
    functions: std.ArrayList(Function),
    exports: Exports,
    stack: Stack,
    callstack: std.ArrayList(StackFrame),

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
            .exports = Exports{
                .functions = std.ArrayList(Export).init(allocator),
                .tables = std.ArrayList(Export).init(allocator),
                .memories = std.ArrayList(Export).init(allocator),
                .globals = std.ArrayList(Export).init(allocator),
            },
            .stack = Stack.init(allocator),
            .callstack = std.ArrayList(StackFrame).init(allocator),
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
            const version = try reader.readIntBig(u32);
            if (version != 1) {
                return error.UnsupportedWasmVersion;
            }
        }

        while (stream.pos < stream.buffer.len) {
            const section_id: Section = @intToEnum(Section, try reader.readByte());
            const size_bytes: usize = try reader.readIntBig(u32);
            switch (section_id) {
                .FunctionType => {
                    // std.debug.print("parseWasm: section: FunctionType\n", .{});
                    const num_types = try reader.readIntBig(u32);
                    var types_index:u32 = 0;
                    while (types_index < num_types) {
                        const sentinel = try reader.readByte();
                        if (sentinel != function_type_sentinel_byte) {
                            return error.InvalidBytecode;
                        }

                        const num_params = try reader.readIntBig(u32);

                        var func = FunctionType{ .numParams = num_params, .types = std.ArrayList(Type).init(allocator) };
                        errdefer func.types.deinit();

                        var params_left = num_params;
                        while (params_left > 0) {
                            params_left -= 1;

                            var param_type = @intToEnum(Type, try reader.readByte());
                            try func.types.append(param_type);
                        }

                        const num_returns = try reader.readIntBig(u32);
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

                    const num_funcs = try reader.readIntBig(u32);
                    var func_index:u32 = 0;
                    while (func_index < num_funcs) {
                        var func = Function{
                            .typeIndex = try reader.readIntBig(u32),
                            .bytecodeOffset = 0, // we'll fix these up later when we find them in the Code section
                            .locals = std.ArrayList(Type).init(allocator),
                        };
                        errdefer func.locals.deinit();
                        try vm.functions.append(func);

                        func_index += 1;
                    }
                },
                .Export => {
                    // std.debug.print("parseWasm: section: Export\n", .{});

                    const num_exports = try reader.readIntBig(u32);

                    var export_index:u32 = 0;
                    while (export_index < num_exports)
                    {
                        const name_length = try reader.readIntBig(u32);
                        var name = std.ArrayList(u8).init(allocator);
                        try name.resize(name_length);
                        errdefer name.deinit();
                        _ = try stream.read(name.items);

                        const exportType = @intToEnum(ExportType, try reader.readByte());
                        const exportIndex = try reader.readIntBig(u32);
                        switch (exportType) {
                            .Function => {
                                if (exportIndex >= vm.functions.items.len) {
                                    return error.InvalidExport;
                                }
                                const export_ = Export{ .name = name, .index = exportIndex };
                                try vm.exports.functions.append(export_);
                            },
                            else => {},
                        }

                        export_index += 1;
                    }
                },

                .Code => {
                    // std.debug.print("parseWasm: section: Code\n", .{});

                    const num_codes = try reader.readIntBig(u32);
                    var code_index: u32 = 0;
                    while (code_index < num_codes) {
                        var code_size = try reader.readIntBig(u32);
                        var code_begin_pos = stream.pos;

                        const num_locals = try reader.readIntBig(u32);
                        var locals_index: u32 = 0;
                        while (locals_index < num_locals) {
                            locals_index += 1;
                            const local_type = @intToEnum(Type, try reader.readByte());
                            try vm.functions.items[code_index].locals.append(local_type);
                        }

                        vm.functions.items[code_index].bytecodeOffset = @intCast(u32, stream.pos);

                        try stream.seekTo(code_begin_pos);
                        try stream.seekBy(code_size); // skip the function body, TODO validation later

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
        self.stack.deinit();
        self.callstack.deinit();
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
                defer locals.deinit();
                try locals.resize(func.locals.items.len);
                for (params) |v, i| {
                    locals.items[i] = v;
                }

                try self.callstack.append(StackFrame{ .func = &func, .stackBaseIndex = 0, .locals = locals.items });
                try self.executeBytecode(func.bytecodeOffset);

                if (self.stack.size() != returns.len) {
                    // std.debug.print("stack size: {}, returns.len: {}\n", .{self.stack.size(), returns.len});
                    return error.TypeMismatch;
                }

                if (returns.len > 0) {
                    var index: i32 = @intCast(i32, returns.len - 1);
                    while (index >= 0) {
                        // std.debug.print("stack size: {}, index: {}\n", .{self.stack.size(), index});
                        returns[@intCast(usize, index)] = try self.stack.pop();
                        index -= 1;
                    }
                }
                return;
            }
        }

        return error.UnknownExport;
    }

    fn executeBytecode(self: *Self, bytecodeOffset: u32) !void {
        var stream = std.io.fixedBufferStream(self.bytecode);
        try stream.seekTo(bytecodeOffset);
        var reader = stream.reader();

        while (stream.pos < stream.buffer.len) {
            const instruction: Instruction = @intToEnum(Instruction, try reader.readByte());

            switch (instruction) {
                Instruction.Unreachable => {
                    return error.Unreachable;
                },
                Instruction.Noop => {},
                Instruction.End => {
                    return;
                    // return from function for now. in the future needs to handle returning from blocks
                },
                Instruction.Local_Get => {
                    var locals_index = try reader.readIntBig(u32);
                    var stackframe:StackFrame = self.callstack.items[self.callstack.items.len - 1];
                    var v:TypedValue = stackframe.locals[locals_index];
                    try self.stack.push(v);
                },
                Instruction.Local_Set => {
                    var locals_index = try reader.readIntBig(u32);
                    var stackframe:StackFrame = self.callstack.items[self.callstack.items.len - 1];
                    var v:TypedValue = try self.stack.pop();
                    stackframe.locals[locals_index] = v;
                },
                Instruction.Local_Tee => {
                    var locals_index = try reader.readIntBig(u32);
                    var stackframe:StackFrame = self.callstack.items[self.callstack.items.len - 1];
                    var v:TypedValue = try self.stack.top();
                    stackframe.locals[locals_index] = v;
                },
                Instruction.I32_Const => {
                    if (stream.pos + 3 >= stream.buffer.len) {
                        return error.IncompleteInstruction;
                    }

                    var v: i32 = try reader.readIntBig(i32);
                    try self.stack.push_i32(v);
                },
                Instruction.I32_Eqz => {
                    var v1: i32 = try self.stack.pop_i32();
                    var result: i32 = if (v1 == 0) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_Eq => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result: i32 = if (v1 == v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_NE => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result: i32 = if (v1 != v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_LT_S => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_LT_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var result: i32 = if (v1 < v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_GT_S => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_GT_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var result: i32 = if (v1 > v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_LE_S => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_LE_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var result: i32 = if (v1 <= v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_GE_S => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_GE_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var result: i32 = if (v1 >= v2) 1 else 0;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_Add => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result = v1 + v2;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_Sub => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var result = v1 - v2;
                    try self.stack.push_i32(result);
                },
                Instruction.I32_Mul => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var value = v1 * v2;
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Div_S => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var value = try std.math.divTrunc(i32, v1, v2);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Div_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var value_unsigned = try std.math.divFloor(u32, v1, v2);
                    var value = @bitCast(i32, value_unsigned);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Rem_S => {
                    var v2: i32 = try self.stack.pop_i32();
                    var v1: i32 = try self.stack.pop_i32();
                    var value = @rem(v1, v2);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Rem_U => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var value = @bitCast(i32, v1 % v2);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_And => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var value = @bitCast(i32, v1 & v2);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Or => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var value = @bitCast(i32, v1 | v2);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Xor => {
                    var v2: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var v1: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var value = @bitCast(i32, v1 ^ v2);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Shl => {
                    var shift_unsafe: i32 = try self.stack.pop_i32();
                    var int: i32 = try self.stack.pop_i32();
                    var shift = @intCast(u5, shift_unsafe);
                    var value = int << shift;
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Shr_S => {
                    var shift_unsafe: i32 = try self.stack.pop_i32();
                    var int: i32 = try self.stack.pop_i32();
                    var shift = @intCast(u5, shift_unsafe);
                    var value = int >> shift;
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Shr_U => {
                    var shift_unsafe: i32 = try self.stack.pop_i32();
                    var int: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var shift = @intCast(u5, shift_unsafe);
                    var value = @bitCast(i32, int >> shift);
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Rotl => {
                    var rot: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var int: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var value = @bitCast(i32, std.math.rotl(u32, int, rot));
                    try self.stack.push_i32(value);
                },
                Instruction.I32_Rotr => {
                    var rot: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var int: u32 = @bitCast(u32, try self.stack.pop_i32());
                    var value = @bitCast(i32, std.math.rotr(u32, int, rot));
                    try self.stack.push_i32(value);
                },
                // else => return error.UnknownInstruction,
            }
        }
    }
};

const WasmBuilder = struct {
    const Self = @This();

    const BuilderFunction = struct {
        exportName: std.ArrayList(u8),
        ftype: FunctionType,
        locals: std.ArrayList(Type),
        instructions: std.ArrayList(u8),
    };

    allocator: *std.mem.Allocator,
    functions: std.ArrayList(BuilderFunction),
    bytecode: std.ArrayList(u8),
    needsRebuild: bool = true,

    fn init(allocator: *std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .functions = std.ArrayList(BuilderFunction).init(allocator),
            .bytecode = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(self: *Self) void {
        for (self.functions.items) |func| {
            func.exportName.deinit();
            func.ftype.types.deinit();
            func.locals.deinit();
            func.instructions.deinit();
        }
        self.functions.deinit();
        self.bytecode.deinit();
    }

    fn addFunc(self: *Self, optionalName: ?[]const u8, params: []const Type, returns: []const Type, locals: []const Type, instructions: []const u8) !void {
        var f = BuilderFunction{
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

        if (optionalName) |name| {
            try f.exportName.appendSlice(name);
        }

        try f.ftype.types.appendSlice(params);
        try f.ftype.types.appendSlice(returns);
        try f.locals.appendSlice(locals);
        try f.instructions.appendSlice(instructions);

        try self.functions.append(f);

        self.needsRebuild = true;
    }

    fn buildBytecode(self: *Self) !void {
        const LocalHelpers = struct{
            fn WriteU32AtOffset(sectionBytes: []u8, offset:usize, value:u32) !void {
                std.debug.assert(offset < sectionBytes.len);
                var stream = std.io.fixedBufferStream(sectionBytes);
                stream.pos = offset;
                var writer = stream.writer();
                try writer.writeIntBig(u32, @intCast(u32, value));
            }

            fn WriteSectionSize(sectionBytes: []u8) !void {
                const section_header_bytesize: usize = @sizeOf(u8) + @sizeOf(u32);

                try WriteU32AtOffset(sectionBytes, 1, @intCast(u32, sectionBytes.len - section_header_bytesize));
            }
        };

        self.bytecode.clearRetainingCapacity();

        // dedupe function types
        const FunctionTypeSetType = std.HashMap(*FunctionType, *FunctionType, FunctionTypeContext, std.hash_map.default_max_load_percentage);
        var functionTypeSet = FunctionTypeSetType.init(self.allocator);
        defer functionTypeSet.deinit();

        // std.debug.print("self.functions.items: {s}\n", .{self.functions.items});
        for (self.functions.items) |*func| {
            _ = try functionTypeSet.getOrPut(&func.ftype);
        }

        var functionTypesSorted = std.ArrayList(*FunctionType).init(self.allocator);
        defer functionTypesSorted.deinit();
        try functionTypesSorted.ensureCapacity(functionTypeSet.count());
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

        // types section
        var sectionFunctionTypes = std.ArrayList(u8).init(self.allocator);
        defer sectionFunctionTypes.deinit();
        {
            var writer = sectionFunctionTypes.writer();

            try writer.writeByte(@enumToInt(Section.FunctionType));
            try writer.writeIntBig(u32, 0); // placeholder for size

            try writer.writeIntBig(u32, @intCast(u32, functionTypesSorted.items.len));
            for (functionTypesSorted.items) |funcType| {
                try writer.writeByte(function_type_sentinel_byte);

                var params = funcType.getParams();
                var returns = funcType.getReturns();

                try writer.writeIntBig(u32, @intCast(u32, params.len));
                for (params) |v| {
                    try writer.writeByte(@enumToInt(v));
                }
                try writer.writeIntBig(u32, @intCast(u32, returns.len));
                for (returns) |v| {
                    try writer.writeByte(@enumToInt(v));
                }
            }

            try LocalHelpers.WriteSectionSize(sectionFunctionTypes.items);
        }

        // function section
        var sectionFunctions = std.ArrayList(u8).init(self.allocator);
        defer sectionFunctions.deinit();
        {
            var writer = sectionFunctions.writer();

            try writer.writeByte(@enumToInt(Section.Function));
            try writer.writeIntBig(u32, 0); // placeholder size

            try writer.writeIntBig(u32, @intCast(u32, self.functions.items.len));
            for (self.functions.items) |*func| {
                var index: ?usize = std.sort.binarySearch(*FunctionType, &func.ftype, functionTypesSorted.items, FunctionTypeContext{}, FunctionTypeContext.order);
                try writer.writeIntBig(u32, @intCast(u32, index.?));
            }

            try LocalHelpers.WriteSectionSize(sectionFunctions.items);
        }

        // exports section
        var sectionExports = std.ArrayList(u8).init(self.allocator);
        defer sectionExports.deinit();
        {
            var writer = sectionExports.writer();

            try writer.writeByte(@enumToInt(Section.Export));
            try writer.writeIntBig(u32, 0);

            const num_exports_pos = sectionExports.items.len;
            try writer.writeIntBig(u32, 0); // placeholder num exports

            var num_exports:u32 = 0;
            for (self.functions.items) |func, i|
            {
                if (func.exportName.items.len > 0) {
                    num_exports += 1;

                    try writer.writeIntBig(u32, @intCast(u32, func.exportName.items.len));
                    _ = try writer.write(func.exportName.items);
                    try writer.writeByte(@enumToInt(ExportType.Function));
                    try writer.writeIntBig(u32, @intCast(u32, i));
                }
            }

            try LocalHelpers.WriteU32AtOffset(sectionExports.items, num_exports_pos, num_exports);
            try LocalHelpers.WriteSectionSize(sectionExports.items);
        }

        // code section
        var sectionCode = std.ArrayList(u8).init(self.allocator);
        defer sectionCode.deinit();
        {
            var writer = sectionCode.writer();

            try writer.writeByte(@enumToInt(Section.Code));
            try writer.writeIntBig(u32, 0); // placeholder size

            try writer.writeIntBig(u32, @intCast(u32, self.functions.items.len));
            for (self.functions.items) |func| {
                const code_size_pos = sectionCode.items.len;
                try writer.writeIntBig(u32, 0); //placeholder code size

                const code_begin_pos = sectionCode.items.len;

                try writer.writeIntBig(u32, @intCast(u32, func.locals.items.len));
                for (func.locals.items) |local| {
                    try writer.writeByte(@enumToInt(local));
                }
                _ = try writer.write(func.instructions.items);
                // TODO should the client supply an end instruction instead?
                try writer.writeByte(@enumToInt(Instruction.End));

                const code_end_pos = sectionCode.items.len;
                const code_size = @intCast(u32, code_end_pos - code_begin_pos);

                try LocalHelpers.WriteU32AtOffset(sectionCode.items, code_size_pos, code_size);
            }

            try LocalHelpers.WriteSectionSize(sectionCode.items);
        }

        // stitch all sections
        const header = [_]u8{
            0x00, 0x61, 0x73, 0x6D,
            0x00, 0x00, 0x00, 0x01,
        };

        try self.bytecode.appendSlice(&header);
        try self.bytecode.appendSlice(sectionFunctionTypes.items);
        try self.bytecode.appendSlice(sectionFunctions.items);
        try self.bytecode.appendSlice(sectionExports.items);
        try self.bytecode.appendSlice(sectionCode.items);
    }

    fn getBytecode(self: *Self) ![]const u8 {
        if (self.needsRebuild) {
            try self.buildBytecode();
        }

        return self.bytecode.items;
    }
};

fn testExecuteAndExpect(bytecode: []const u8, optionalParams:?[]TypedValue, optionalLocals:?[]Type, expectedReturns:?[]TypedValue) !void {
    var builder = WasmBuilder.init(std.testing.allocator);
    defer builder.deinit();

    {
        var params = std.ArrayList(Type).init(std.testing.allocator);
        var returns = std.ArrayList(Type).init(std.testing.allocator);
        defer params.deinit();
        defer returns.deinit();

        if (optionalParams) |values| {
            for (values) |v| {
                try params.append(std.meta.activeTag(v));
            }
        }

        if (expectedReturns) |values| {
            for (values) |v| {
                var t = std.meta.activeTag(v);
                try returns.append(t);
            }
        }

        const locals = optionalLocals orelse &[_]Type{};
        try builder.addFunc("testFunc", params.items, returns.items, locals, bytecode);
    }

    const rebuiltBytecode = try builder.getBytecode();

    var vm = try VmState.parseWasm(rebuiltBytecode, .UseExisting, std.testing.allocator);
    defer vm.deinit();

    var params = std.ArrayList(TypedValue).init(std.testing.allocator);
    defer params.deinit();
    if (optionalParams) |values| {
        for (values) |v| {
            try params.append(v);
        }
    }

    var returns = std.ArrayList(TypedValue).init(std.testing.allocator);
    defer returns.deinit();

    if (expectedReturns) |expected| {
        try returns.resize(expected.len);
    }

    try vm.callFunc("testFunc", params.items, returns.items);

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

fn testExecuteAndExpectU32Return(bytecode: []const u8, expected:u32) !void {
    var expectedReturns = [_]TypedValue{.{.I32 = @bitCast(i32, expected)}};
    try testExecuteAndExpect(bytecode, null, null, &expectedReturns);
}

fn testExecute(bytecode: []const u8) !void {
    try testExecuteAndExpect(bytecode, null, null, null);
}

test "wasm builder" {
    var builder = WasmBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.addFunc("abcd", &[_]Type{.I64}, &[_]Type{.I32}, &[_]Type{ .I32, .I64 }, &[_]u8{ 0x01, 0x01, 0x01, 0x01 });
    var bytecode = try builder.getBytecode();

    // std.debug.print("bytecode: \n\t", .{});
    // var tab:u32 = 0;
    // for (bytecode) |byte| {
    //     if (tab == 4) {
    //         std.debug.print("\n\t", .{});
    //         tab = 0;
    //     }
    //     tab += 1;
    //     std.debug.print("0x{X:2} ", .{byte});
    // }

    // zig fmt: off
    const expected = [_]u8{
        0x00, 0x61, 0x73, 0x6D, // magic
        0x00, 0x00, 0x00, 0x01, // version
        @enumToInt(Section.FunctionType),
        0x00, 0x00, 0x00, 0x0F, // section size
        0x00, 0x00, 0x00, 0x01, // num types
        function_type_sentinel_byte,
        0x00, 0x00, 0x00, 0x01, // num params
        @enumToInt(Type.I64),
        0x00, 0x00, 0x00, 0x01, // num returns
        @enumToInt(Type.I32),
        @enumToInt(Section.Function),
        0x00, 0x00, 0x00, 0x08, // section size
        0x00, 0x00, 0x00, 0x01, // num functions
        0x00, 0x00, 0x00, 0x00, // index to types
        @enumToInt(Section.Export),
        0x00, 0x00, 0x00, 0x11, // section size
        0x00, 0x00, 0x00, 0x01, // num exports
        0x00, 0x00, 0x00, 0x04, // size of export name (1)
        0x61, 0x62, 0x63, 0x64, // "abcd"
        @enumToInt(ExportType.Function),
        0x00, 0x00, 0x00, 0x00, // index of export
        @enumToInt(Section.Code),
        0x00, 0x00, 0x00, 0x13, // section size
        0x00, 0x00, 0x00, 0x01, // num codes
        0x00, 0x00, 0x00, 0x0B, // code size
        0x00, 0x00, 0x00, 0x02, // num locals
        @enumToInt(Type.I32), @enumToInt(Type.I64),     // local array
        0x01, 0x01, 0x01, 0x01, // bytecode
        0x0B,                   // function end
    };
    // zig fmt: on

    try std.testing.expect(std.mem.eql(u8, bytecode, &expected));
}

test "unreachable" {
    var bytecode = [_]u8{
        0x00,
    };

    var didCatchError:bool = false;
    var didCatchCorrectError:bool = false;

    testExecute(&bytecode) catch |e| {
        didCatchError = true;
        didCatchCorrectError = (e == VMError.Unreachable);
    };

    try std.testing.expect(didCatchError);
    try std.testing.expect(didCatchCorrectError);
}

test "noop" {
    var bytecode = [_]u8{
        0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01,
    };
    try testExecute(&bytecode);
}

test "local_get" {
    var bytecode = [_]u8{
        0x20, 
        0x00, 0x00, 0x00, 0x00,
    };
    var params = [_]TypedValue{.{.I32 = 0x1337}};
    var locals = [_]Type{.I32};
    var expected = [_]TypedValue{.{.I32 = 0x1337}};
    try testExecuteAndExpect(&bytecode, &params, &locals, &expected);
}

test "local_set" {
    var bytecode = [_]u8{
        0x41, // set constant values on stack
        0x00, 0x00, 0x13, 0x37,
        0x41,
        0x00, 0x00, 0x13, 0x36,
        0x41,
        0x00, 0x00, 0x13, 0x35,
        0x21, // pop stack value and set in local
        0x00, 0x00, 0x00, 0x00,
        0x21,
        0x00, 0x00, 0x00, 0x00,
        0x21,
        0x00, 0x00, 0x00, 0x00,
        0x20, // push local value onto stack, should be 1337 since it was the first pushed
        0x00, 0x00, 0x00, 0x00,
    };
    var params = [_]TypedValue{};
    var locals = [_]Type{.I32};
    var expected = [_]TypedValue{.{.I32 = 0x1337}};
    try testExecuteAndExpect(&bytecode, &params, &locals, &expected);
}

test "local_tee" {
    var bytecode = [_]u8{
        0x41, // set constant value on stack
        0x00, 0x00, 0x13, 0x37,
        0x22, // leave value on stack but also put it in locals
        0x00, 0x00, 0x00, 0x00,
        0x20, // push local onto stack
        0x00, 0x00, 0x00, 0x00,
        0x6A, // add 2 stack values, 0x1337 + 0x1337 = 0x266E
    };
    var params = [_]TypedValue{.{.I32 = 0x1337}};
    var locals = [_]Type{.I32};
    var expected = [_]TypedValue{.{.I32 = 0x266E}};
    try testExecuteAndExpect(&bytecode, &params, &locals, &expected);
}


test "i32_eqz" {
    var bytecode1 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x45,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x01,
        0x45,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x0);
}

test "i32_eq" {
    var bytecode1 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x46,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x80, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x46,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x0);
}

test "i32_ne" {
    var bytecode1 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x47,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x80, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x47,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x1);
}

test "i32_lt_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x48,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x48,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x0);
}

test "i32_lt_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x49,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x49,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x1);
}

test "i32_gt_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4A,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4A,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x1);
}

test "i32_gt_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4B,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x4B,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x0);
}

test "i32_le_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4C,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4C,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x0);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4C,
    };
    try testExecuteAndExpectU32Return(&bytecode3, 0x1);
}

test "i32_le_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4D,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4D,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x1);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4D,
    };
    try testExecuteAndExpectU32Return(&bytecode3, 0x1);
}

test "i32_ge_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4E,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4E,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x1);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4E,
    };
    try testExecuteAndExpectU32Return(&bytecode3, 0x1);
}

test "i32_ge_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4F,
    };
    try testExecuteAndExpectU32Return(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4F,
    };
    try testExecuteAndExpectU32Return(&bytecode2, 0x0);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4F,
    };
    try testExecuteAndExpectU32Return(&bytecode3, 0x1);
}

test "i32_add" {
    var bytecode = [_]u8{
        0x41, 0x00, 0x10, 0x00, 0x01,
        0x41, 0x00, 0x00, 0x02, 0x01,
        0x6A,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x100202);
}

test "i32_sub" {
    var bytecode = [_]u8{
        0x41, 0x00, 0x10, 0x00, 0x01,
        0x41, 0x00, 0x00, 0x02, 0x01,
        0x6B,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0xFFE00);
}

test "i32_mul" {
    var bytecode = [_]u8{
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x41, 0x00, 0x00, 0x03, 0x00,
        0x6C,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x60000);
}

test "i32_div_s" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x6D,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0xFFFFFFFD); //-3
}

test "i32_div_u" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x00, 0x06, 0x00,
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x6E,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x400003);
}

test "i32_rem_s" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0xFF, 0xF9, 0x9A, // -0x666
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x6F,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0xFFFFFF9A); // -0x66
}

test "i32_rem_u" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x00, 0x06, 0x66,
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x70,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x66);
}

test "i32_and" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0xFF, 0xFF, 0xFF,
        0x41, 0x11, 0x22, 0x33, 0x44,
        0x71,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x11223344);
}

test "i32_or" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0x00, 0xFF, 0x00,
        0x41, 0x11, 0x22, 0x33, 0x44,
        0x72,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0xFF22FF44);
}

test "i32_xor" {
    var bytecode = [_]u8{
        0x41, 0xF0, 0xF0, 0xF0, 0xF0,
        0x41, 0x0F, 0x0F, 0xF0, 0xF0,
        0x73,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0xFFFF0000);
}

test "i32_shl" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x02,
        0x74,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x40404);
}

test "i32_shr_s" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x01,
        0x75,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0xC0008080);
}

test "i32_shr_u" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x01,
        0x76,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x40008080);
}

test "i32_rotl" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x02,
        0x77,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x00040406);
}

test "i32_rotr" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x02,
        0x78,
    };
    try testExecuteAndExpectU32Return(&bytecode, 0x60004040);
}
