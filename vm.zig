const std = @import("std");

const VMError = error {
    Unreachable,
    IncompleteInstruction,
    UnknownInstruction,
    TypeMismatch,
};

const Instruction = enum(u8) {
    Unreachable = 0x00,
    Noop = 0x01,
    I32_Const = 0x41,
    I32_Add = 0x6A,
    I32_Sub = 0x6B,
    I32_Mul = 0x6C,
};

const Type = enum {
    I32,
    I64,
    F32,
    F64,
};

const TypedValue = union(Type) {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
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

    fn pop(self: *Self) TypedValue {
        return self.stack.orderedRemove(self.stack.items.len - 1);
    }

    fn push(self: *Self, v: TypedValue) !void {
        try self.stack.append(v);
    }

    fn pop_i32(self: *Self) !i32 {
        var typed:TypedValue = self.pop();
        switch (typed) {
            Type.I32 => |value| return value,
            else => return error.TypeMismatch,
        }
    }

    fn push_i32(self: *Self, v:i32) !void {
        var typed = TypedValue{.I32 = v};
        try self.push(typed);
    }

    fn size(self: *Self) usize {
        return self.stack.items.len;
    }

    stack: std.ArrayList(TypedValue),
};

fn executeBytecode(bytecode: []const u8, stack: *Stack) !i32 {
    var index:usize = 0;

    while (index < bytecode.len) {
        const instruction:Instruction = @intToEnum(Instruction, bytecode[index]);
        index += 1;

        switch (instruction) {
            Instruction.Unreachable => {
                return error.Unreachable;
            },
            Instruction.Noop => {
                index += 1;
            },
            Instruction.I32_Const => {
                var v:i32 = 0;

                if (index + 3 >= bytecode.len) {
                    return error.IncompleteInstruction;
                }

                // little endian
                // v = v | @shlExact(@as(bytecode[index + 0], i32), 0);
                // v = v | @shlExact(@as(bytecode[index + 1], i32), 8);
                // v = v | @shlExact(@as(bytecode[index + 2], i32), 16);
                // v = v | @shlExact(@as(bytecode[index + 3], i32), 24);

                // big endian
                v = v | @shlExact(@as(i32, bytecode[index + 0]), 24);
                v = v | @shlExact(@as(i32, bytecode[index + 1]), 16);
                v = v | @shlExact(@as(i32, bytecode[index + 2]), 8);
                v = v | @shlExact(@as(i32, bytecode[index + 3]), 0);

                try stack.push_i32(v);

                index += 4;
            },
            Instruction.I32_Add => {
                var v2:i32 = try stack.pop_i32();
                var v1:i32 = try stack.pop_i32();
                var result = v1 + v2;
                try stack.push_i32(result);
            },
            Instruction.I32_Sub => {
                var v2:i32 = try stack.pop_i32();
                var v1:i32 = try stack.pop_i32();
                var result = v1 - v2;
                try stack.push_i32(result);
            },
            Instruction.I32_Mul => {
                var v2:i32 = try stack.pop_i32();
                var v1:i32 = try stack.pop_i32();
                var value = v1 * v2;
                try stack.push_i32(value);
            }
            // else => return error.UnknownInstruction,
        }
    }

    if (stack.size() > 0) {
        return try stack.pop_i32();
    }

    return 0;
}

test "unreachable" {
    var bytecode = [_]u8{ 0x00, };

    var stack = Stack.init(std.testing.allocator);
    defer stack.deinit();

    const result = executeBytecode(&bytecode, &stack);
    if (result) |_| {
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expect(err == VMError.Unreachable);   
    }
}

test "noop" {
    var bytecode = [_]u8{   0x01, 0x01, 0x01, 0x01, 0x01, 
                            0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01,  };

    var stack = Stack.init(std.testing.allocator);
    defer stack.deinit();

    var result:i32 = try executeBytecode(&bytecode, &stack);
    try std.testing.expect(0x0 == result);
}

test "i32_add" {
    var bytecode = [_]u8{   0x41, 0x00, 0x10, 0x00, 0x01,
                            0x41, 0x00, 0x00, 0x02, 0x01,
                            0x6A, };

    var stack = Stack.init(std.testing.allocator);
    defer stack.deinit();

    var result:i32 = try executeBytecode(&bytecode, &stack);
    try std.testing.expect(0x100202 == result);
}

test "i32_sub" {
    var bytecode = [_]u8{   0x41, 0x00, 0x10, 0x00, 0x01,
                            0x41, 0x00, 0x00, 0x02, 0x01,
                            0x6B, };

    var stack = Stack.init(std.testing.allocator);
    defer stack.deinit();

    var result:i32 = try executeBytecode(&bytecode, &stack);
    try std.testing.expect(0xFFE00 == result);
}

test "i32_mul" {
    var bytecode = [_]u8{   0x41, 0x00, 0x00, 0x02, 0x00,
                            0x41, 0x00, 0x00, 0x03, 0x00,
                            0x6C, };

    var stack = Stack.init(std.testing.allocator);
    defer stack.deinit();

    var result:i32 = try executeBytecode(&bytecode, &stack);
    try std.testing.expect(0x60000 == result);
}

test "i32_div" {
    var bytecode = [_]u8{   0x41, 0x00, 0x00, 0x02, 0x00,
                            0x41, 0x00, 0x00, 0x03, 0x00,
                            0x6C, };

    var stack = Stack.init(std.testing.allocator);
    defer stack.deinit();

    var result:i32 = try executeBytecode(&bytecode, &stack);
    try std.testing.expect(0x60000 == result);
}