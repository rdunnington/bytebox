const std = @import("std");

const VMError = error{
    Unreachable,
    IncompleteInstruction,
    UnknownInstruction,
    TypeMismatch,
};

const Instruction = enum(u8) {
    Unreachable = 0x00,
    Noop = 0x01,
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

    fn pop(self: *Self) TypedValue {
        return self.stack.orderedRemove(self.stack.items.len - 1);
    }

    fn push(self: *Self, v: TypedValue) !void {
        try self.stack.append(v);
    }

    fn pop_i32(self: *Self) !i32 {
        var typed: TypedValue = self.pop();
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

fn executeBytecode(bytecode: []const u8, stack: *Stack) !i32 {
    var stream = std.io.fixedBufferStream(bytecode);
    var reader = stream.reader();

    while (stream.pos < stream.buffer.len) {
        const instruction: Instruction = @intToEnum(Instruction, try reader.readByte());

        switch (instruction) {
            Instruction.Unreachable => {
                return error.Unreachable;
            },
            Instruction.Noop => {},
            Instruction.I32_Const => {
                if (stream.pos + 3 >= stream.buffer.len) {
                    return error.IncompleteInstruction;
                }

                var v: i32 = try reader.readIntBig(i32);
                try stack.push_i32(v);
            },
            Instruction.I32_Eqz => {
                var v1: i32 = try stack.pop_i32();
                var result: i32 = if (v1 == 0) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_Eq => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result: i32 = if (v1 == v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_NE => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result: i32 = if (v1 != v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_LT_S => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result: i32 = if (v1 < v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_LT_U => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var result: i32 = if (v1 < v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_GT_S => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result: i32 = if (v1 > v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_GT_U => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var result: i32 = if (v1 > v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_LE_S => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result: i32 = if (v1 <= v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_LE_U => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var result: i32 = if (v1 <= v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_GE_S => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result: i32 = if (v1 >= v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_GE_U => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var result: i32 = if (v1 >= v2) 1 else 0;
                try stack.push_i32(result);
            },
            Instruction.I32_Add => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result = v1 + v2;
                try stack.push_i32(result);
            },
            Instruction.I32_Sub => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var result = v1 - v2;
                try stack.push_i32(result);
            },
            Instruction.I32_Mul => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var value = v1 * v2;
                try stack.push_i32(value);
            },
            Instruction.I32_Div_S => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var value = try std.math.divTrunc(i32, v1, v2);
                try stack.push_i32(value);
            },
            Instruction.I32_Div_U => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var value_unsigned = try std.math.divFloor(u32, v1, v2);
                var value = @bitCast(i32, value_unsigned);
                try stack.push_i32(value);
            },
            Instruction.I32_Rem_S => {
                var v2: i32 = try stack.pop_i32();
                var v1: i32 = try stack.pop_i32();
                var value = @rem(v1, v2);
                try stack.push_i32(value);
            },
            Instruction.I32_Rem_U => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var value = @bitCast(i32, v1 % v2);
                try stack.push_i32(value);
            },
            Instruction.I32_And => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var value = @bitCast(i32, v1 & v2);
                try stack.push_i32(value);
            },
            Instruction.I32_Or => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var value = @bitCast(i32, v1 | v2);
                try stack.push_i32(value);
            },
            Instruction.I32_Xor => {
                var v2: u32 = @bitCast(u32, try stack.pop_i32());
                var v1: u32 = @bitCast(u32, try stack.pop_i32());
                var value = @bitCast(i32, v1 ^ v2);
                try stack.push_i32(value);
            },
            Instruction.I32_Shl => {
                var shift_unsafe: i32 = try stack.pop_i32();
                var int: i32 = try stack.pop_i32();
                var shift = @intCast(u5, shift_unsafe);
                var value = int << shift;
                try stack.push_i32(value);
            },
            Instruction.I32_Shr_S => {
                var shift_unsafe: i32 = try stack.pop_i32();
                var int: i32 = try stack.pop_i32();
                var shift = @intCast(u5, shift_unsafe);
                var value = int >> shift;
                try stack.push_i32(value);
            },
            Instruction.I32_Shr_U => {
                var shift_unsafe: i32 = try stack.pop_i32();
                var int: u32 = @bitCast(u32, try stack.pop_i32());
                var shift = @intCast(u5, shift_unsafe);
                var value = @bitCast(i32, int >> shift);
                try stack.push_i32(value);
            },
            Instruction.I32_Rotl => {
                var rot: u32 = @bitCast(u32, try stack.pop_i32());
                var int: u32 = @bitCast(u32, try stack.pop_i32());
                var value = @bitCast(i32, std.math.rotl(u32, int, rot));
                try stack.push_i32(value);
            },
            Instruction.I32_Rotr => {
                var rot: u32 = @bitCast(u32, try stack.pop_i32());
                var int: u32 = @bitCast(u32, try stack.pop_i32());
                var value = @bitCast(i32, std.math.rotr(u32, int, rot));
                try stack.push_i32(value);
            },
            // else => return error.UnknownInstruction,
        }
    }

    if (stack.size() > 0) {
        return try stack.pop_i32();
    }

    return 0;
}

fn testExecuteAndExpect(bytecode: []const u8, expected: u32) !void {
    var stack = Stack.init(std.testing.allocator);
    defer stack.deinit();

    var result: i32 = try executeBytecode(bytecode, &stack);
    var result_u32 = @bitCast(u32, result);
    if (result_u32 != expected) {
        std.debug.print("expected: 0x{X}, result: 0x{X}\n", .{ @bitCast(u32, expected), result_u32 });
    }
    try std.testing.expect(expected == result_u32);
}

test "unreachable" {
    var bytecode = [_]u8{
        0x00,
    };

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
    var bytecode = [_]u8{
        0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01,
    };
    try testExecuteAndExpect(&bytecode, 0x0);
}

test "i32_eqz" {
    var bytecode1 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x45,
    };
    try testExecuteAndExpect(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x01,
        0x45,
    };
    try testExecuteAndExpect(&bytecode2, 0x0);
}

test "i32_eq" {
    var bytecode1 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x46,
    };
    try testExecuteAndExpect(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x80, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x46,
    };
    try testExecuteAndExpect(&bytecode2, 0x0);
}

test "i32_ne" {
    var bytecode1 = [_]u8{
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x47,
    };
    try testExecuteAndExpect(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x80, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00,
        0x47,
    };
    try testExecuteAndExpect(&bytecode2, 0x1);
}

test "i32_lt_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x48,
    };
    try testExecuteAndExpect(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x48,
    };
    try testExecuteAndExpect(&bytecode2, 0x0);
}

test "i32_lt_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x49,
    };
    try testExecuteAndExpect(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x49,
    };
    try testExecuteAndExpect(&bytecode2, 0x1);
}

test "i32_gt_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4A,
    };
    try testExecuteAndExpect(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4A,
    };
    try testExecuteAndExpect(&bytecode2, 0x1);
}

test "i32_gt_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4B,
    };
    try testExecuteAndExpect(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600 (when signed)
        0x4B,
    };
    try testExecuteAndExpect(&bytecode2, 0x0);
}

test "i32_le_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4C,
    };
    try testExecuteAndExpect(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4C,
    };
    try testExecuteAndExpect(&bytecode2, 0x0);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4C,
    };
    try testExecuteAndExpect(&bytecode3, 0x1);
}

test "i32_le_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4D,
    };
    try testExecuteAndExpect(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4D,
    };
    try testExecuteAndExpect(&bytecode2, 0x1);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4D,
    };
    try testExecuteAndExpect(&bytecode3, 0x1);
}

test "i32_ge_s" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4E,
    };
    try testExecuteAndExpect(&bytecode1, 0x0);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4E,
    };
    try testExecuteAndExpect(&bytecode2, 0x1);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4E,
    };
    try testExecuteAndExpect(&bytecode3, 0x1);
}

test "i32_ge_u" {
    var bytecode1 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x4F,
    };
    try testExecuteAndExpect(&bytecode1, 0x1);

    var bytecode2 = [_]u8{
        0x41, 0x00, 0x00, 0x08, 0x00, //  0x800
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4F,
    };
    try testExecuteAndExpect(&bytecode2, 0x0);

    var bytecode3 = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x4F,
    };
    try testExecuteAndExpect(&bytecode3, 0x1);
}

test "i32_add" {
    var bytecode = [_]u8{
        0x41, 0x00, 0x10, 0x00, 0x01,
        0x41, 0x00, 0x00, 0x02, 0x01,
        0x6A,
    };
    try testExecuteAndExpect(&bytecode, 0x100202);
}

test "i32_sub" {
    var bytecode = [_]u8{
        0x41, 0x00, 0x10, 0x00, 0x01,
        0x41, 0x00, 0x00, 0x02, 0x01,
        0x6B,
    };
    try testExecuteAndExpect(&bytecode, 0xFFE00);
}

test "i32_mul" {
    var bytecode = [_]u8{
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x41, 0x00, 0x00, 0x03, 0x00,
        0x6C,
    };
    try testExecuteAndExpect(&bytecode, 0x60000);
}

test "i32_div_s" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0xFF, 0xFA, 0x00, // -0x600
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x6D,
    };
    try testExecuteAndExpect(&bytecode, 0xFFFFFFFD); //-3
}

test "i32_div_u" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x00, 0x06, 0x00,
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x6E,
    };
    try testExecuteAndExpect(&bytecode, 0x400003);
}

test "i32_rem_s" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0xFF, 0xF9, 0x9A, // -0x666
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x6F,
    };
    try testExecuteAndExpect(&bytecode, 0xFFFFFF9A); // -0x66
}

test "i32_rem_u" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x00, 0x06, 0x66,
        0x41, 0x00, 0x00, 0x02, 0x00,
        0x70,
    };
    try testExecuteAndExpect(&bytecode, 0x66);
}

test "i32_and" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0xFF, 0xFF, 0xFF,
        0x41, 0x11, 0x22, 0x33, 0x44,
        0x71,
    };
    try testExecuteAndExpect(&bytecode, 0x11223344);
}

test "i32_or" {
    var bytecode = [_]u8{
        0x41, 0xFF, 0x00, 0xFF, 0x00,
        0x41, 0x11, 0x22, 0x33, 0x44,
        0x72,
    };
    try testExecuteAndExpect(&bytecode, 0xFF22FF44);
}

test "i32_xor" {
    var bytecode = [_]u8{
        0x41, 0xF0, 0xF0, 0xF0, 0xF0,
        0x41, 0x0F, 0x0F, 0xF0, 0xF0,
        0x73,
    };
    try testExecuteAndExpect(&bytecode, 0xFFFF0000);
}

test "i32_shl" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x02,
        0x74,
    };
    try testExecuteAndExpect(&bytecode, 0x40404);
}

test "i32_shr_s" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x01,
        0x75,
    };
    try testExecuteAndExpect(&bytecode, 0xC0008080);
}

test "i32_shr_u" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x01,
        0x76,
    };
    try testExecuteAndExpect(&bytecode, 0x40008080);
}

test "i32_rotl" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x02,
        0x77,
    };
    try testExecuteAndExpect(&bytecode, 0x00040406);
}

test "i32_rotr" {
    var bytecode = [_]u8{
        0x41, 0x80, 0x01, 0x01, 0x01,
        0x41, 0x00, 0x00, 0x00, 0x02,
        0x78,
    };
    try testExecuteAndExpect(&bytecode, 0x60004040);
}
