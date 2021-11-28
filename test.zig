const std = @import("std");
const testing = std.testing;
const wasm = @import("vm.zig");
const Val = wasm.Val;
const print = std.debug.print;

const TestSuiteError = error{
    Fail,
};

const CommandType = enum {
    AssertReturn,
    AssertInvalid,
};

const CommandAssertReturn = struct {
    module: []const u8,
    field: []const u8,
    args: std.ArrayList(Val),
    expected_returns: ?std.ArrayList(Val),
    expected_error: ?anyerror,
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
        // print("parse i32: {s}\n", .{json_value.String});
        const int = std.fmt.parseInt(i32, json_value.String, 10) catch @bitCast(i32, try std.fmt.parseInt(u32, json_value.String, 10));
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
    } else {
        print("Failed to parse value of type '{s}' with value '{s}'\n", .{json_type.String, json_value.String});
    }

    unreachable;
}

fn error_from_text(text: []const u8) anyerror {
    if (strcmp("integer divide by zero", text)) {
        return error.DivisionByZero;
    } else if (strcmp("integer overflow", text)) {
        return error.Overflow;
    }

    unreachable;
}

fn parseCommands(json_path:[]const u8, allocator: *std.mem.Allocator) !std.ArrayList(Command) {
    // print("json_path: {s}\n", .{json_path});
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
            var args = std.ArrayList(Val).init(allocator);
            if (json_args_or_null) |json_args| {
                for (json_args.Array.items) |item| {
                    try args.append(try parseVal(item.Object));
                }
            }

            var expected_returns_or_null: ?std.ArrayList(Val) = null;
            const json_expected_or_null = json_command.Object.get("expected");
            if (json_expected_or_null) |json_expected| {
                var expected_returns = std.ArrayList(Val).init(allocator);
                for (json_expected.Array.items) |item| {
                    try expected_returns.append(try parseVal(item.Object));
                }
                expected_returns_or_null = expected_returns;
            }

            var expected_error: ?anyerror = null;
            const json_text_or_null = json_command.Object.get("text");
            if (json_text_or_null) |text| {
                expected_error = error_from_text(text.String);
            }

            var command = Command{
                .AssertReturn = CommandAssertReturn{
                    .module = fallback_module,
                    .field = try std.mem.dupe(allocator, u8, json_field.String),
                    .args = args,
                    .expected_returns = expected_returns_or_null,
                    .expected_error = expected_error,
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
        } else if (strcmp("assert_trap", json_command_type.String)) {
            print("Skipping assert_trap test...\n", .{});
            // TODO
        } else if (strcmp("assert_malformed", json_command_type.String)) {
            print("Skipping assert_malformed test...\n", .{});
            // TODO
        } else {
            unreachable;
        }
    }

    return commands;
}

fn run(suite_path:[]const u8) !void {
    var did_fail_any_test:bool = false;

    var arena_commands = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_commands.deinit();

    var commands: std.ArrayList(Command) = try parseCommands(suite_path, &arena_commands.allocator);

    const suite_dir = std.fs.path.dirname(suite_path).?;

    for (commands.items) |*command| {

        if (std.meta.activeTag(command.*) == .AssertInvalid) {
            continue;
        }

        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var cwd = std.fs.cwd();
        var module_name = command.getModule();
        var module_path = try std.fs.path.join(&arena.allocator, &[_][]const u8{suite_dir, module_name});

        // print("module_path: {s}\n", .{module_path});

        var module_data = try cwd.readFileAlloc(&arena.allocator, module_path, 1024 * 1024 * 8);
        // wasm.printBytecode("module data", module_data);
        var module_def = try wasm.ModuleDefinition.init(module_data, &arena.allocator);
        var module_inst = try wasm.ModuleInstance.init(&module_def, &arena.allocator);

        switch (command.*) {
            .AssertReturn => |c| {
                const num_expected_returns = if (c.expected_returns) |returns| returns.items.len else 0;
                var returns_placeholder: [8]Val = undefined;
                var returns = returns_placeholder[0..num_expected_returns];
                module_inst.invoke(c.field, c.args.items, returns) catch |e| {
                    if (c.expected_error) |expected| {
                        if (expected != e) {
                            print("AssertReturn: {s}:{s}({s})\n", .{module_path, c.field, c.args.items});
                            print("Fail with error. Expected {}, Actual: {}\n", .{expected, e});
                        }
                    } else {
                        print("AssertReturn: {s}:{s}({s})\n", .{module_path, c.field, c.args.items});
                        print("\tFail with error: {}\n", .{e});
                    }
                };

                if (c.expected_returns) |expected| {
                    for (returns) |r, i| {
                        if (std.meta.eql(r, expected.items[i]) == false) {
                            print("AssertReturn: {s}:{s}({s})\n", .{module_path, c.field, c.args.items});
                            print("\tFail on return {}/{}. Expected: {}, Actual: {}\n", .{i+1, returns.len, expected.items[i], r});
                        }
                        // try std.testing.expect(std.meta.eql(r, c.expected.items[i]));
                    }
                }
            },
            .AssertInvalid => {
                // var returns: [8]Val = undefined;
                // try module.callFunc(c.field, c.args.items, &returns[0..c.expected.items.len]);
            },
        }
    }

    if (did_fail_any_test) {
        return TestSuiteError.Fail;
    }
}

test "i32" {
    try run("test/wasm/i32/i32.json");
}
