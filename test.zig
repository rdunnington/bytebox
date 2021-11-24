const std = @import("std");
const testing = std.testing;
const wasm = @import("vm.zig");
const Val = wasm.Val;

const CommandType = enum {
    AssertReturn,
    AssertInvalid,
};

const CommandAssertReturn = struct {
    module: []const u8,
    field: []const u8,
    args: std.ArrayList(Val),
    expected: std.ArrayList(Val),
};

const CommandAssertInvalid = struct {
    module: []const u8,
    expected: []const u8,
};

const Command = union(CommandType) {
    AssertReturn: CommandAssertReturn,
    AssertInvalid: CommandAssertInvalid,

    fn getModule(self:@This()) []const u8 {
        return switch (self) {
            .AssertReturn => |c| c.module,
            .AssertInvalid => |c| c.module,
        };
    }
};


fn strcmp(a:[]const u8, b:[]const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn parseVal(obj: std.json.ObjectMap) !Val {
    const json_type = obj.get("type").?;
    const json_value = obj.get("value").?;

    if (strcmp("i32", json_type.String)) {
        const int = try std.fmt.parseInt(i32, json_value.String, 10);
        return Val{.I32 = int};
    } else if (strcmp("i64", json_type.String)) {
        const int = try std.fmt.parseInt(i64, json_value.String, 10);
        return Val{.I64 = int};
    } else if (strcmp("f32", json_type.String)) {
        const float = try std.fmt.parseFloat(f32, json_value.String);
        return Val{.F32 = float};
    } else if (strcmp("f64", json_type.String)) {
        const float = try std.fmt.parseFloat(f64, json_value.String);
        return Val{.F64 = float};
    }

    unreachable;
}

fn parseCommands(json_path:[]const u8, allocator: *std.mem.Allocator) !std.ArrayList(Command) {
    var json_data = try std.fs.cwd().readFileAlloc(allocator, json_path, 1024 * 1024 * 8);
    var parser = std.json.Parser.init(allocator, false);
    var tree = try parser.parse(json_data);

    var fallback_module: []const u8 = "";

    var commands = std.ArrayList(Command).init(allocator);

    const json_commands = tree.root.Object.get("commands").?;
    for (json_commands.Array.items) |json_command| {
        const json_command_type = json_command.Object.get("type").?;

        if (strcmp("module", json_command_type.String)) {
            var fallback = json_command.Object.get("filename").?;
            fallback_module = try std.mem.dupe(allocator, u8, fallback.String);
        } else if (strcmp("assert_return", json_command_type.String)) {
            const json_action = json_command.Object.get("action").?;
            const json_field = json_action.Object.get("field").?;
            const json_args_or_null = json_action.Object.get("args");
            const json_expected_or_null = json_action.Object.get("expected");

            var args = std.ArrayList(Val).init(allocator);
            if (json_args_or_null) |json_args| {
                for (json_args.Array.items) |item| {
                    try args.append(try parseVal(item.Object));
                }
            }

            var expected = std.ArrayList(Val).init(allocator);
            if (json_expected_or_null) |json_expected| {
                for (json_expected.Array.items) |item| {
                    try expected.append(try parseVal(item.Object));
                }
            }

            var command = Command{
                .AssertReturn = CommandAssertReturn{
                    .module = fallback_module,
                    .field = try std.mem.dupe(allocator, u8, json_field.String),
                    .args = args,
                    .expected = expected,
                }
            };
            try commands.append(command);
        } else if (strcmp("assert_invalid", json_command_type.String)) {
            const json_filename = json_command.Object.get("filename").?;
            const json_expected = json_command.Object.get("text").?;

            var command = Command{
                .AssertInvalid = CommandAssertInvalid {
                    .module = try std.mem.dupe(allocator, u8, json_filename.String),
                    .expected = try std.mem.dupe(allocator, u8, json_expected.String),
                },
            };
            try commands.append(command);
        } else {
            unreachable;
        }
    }

    return commands;
}

fn run(suite_path:[]const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var commands: std.ArrayList(Command) = try parseCommands(suite_path, &arena.allocator);

    const suite_dir = std.fs.path.dirname(suite_path).?;

    for (commands.items) |*command| {
        var arena_vm = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_vm.deinit();

        var cwd = std.fs.cwd();
        var module_name = command.getModule();
        var module_path = try std.fs.path.join(&arena_vm.allocator, &[_][]const u8{suite_dir, module_name});
        std.debug.print("module_path: {s}\n", .{module_path});
        var module_data = try cwd.readFileAlloc(&arena_vm.allocator, module_path, 1024 * 1024 * 8);
        // wasm.printBytecode("module data", module_data);
        var module = try wasm.VmState.parseWasm(module_data, .UseExisting, &arena_vm.allocator);

        switch (command.*) {
            .AssertReturn => |c| {
                var returns: [8]Val = undefined;
                try module.callFunc(c.field, c.args.items, returns[0..c.expected.items.len]);
                for (returns) |r, i| {
                    try std.testing.expect(std.meta.eql(r, c.expected.items[i]));
                }
            },
            .AssertInvalid => {
                // var returns: [8]Val = undefined;
                // try module.callFunc(c.field, c.args.items, &returns[0..c.expected.items.len]);
            },
        }
    }
}

// test "br" {
//     try run("test/wasm/br/br.json");
// }
