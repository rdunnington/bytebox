const std = @import("std");
const testing = std.testing;
const wasm = @import("vm.zig");
const Val = wasm.Val;
const print = std.debug.print;

var g_verbose_logging = false;

fn log_verbose(comptime msg: []const u8, params: anytype) void {
    if (g_verbose_logging) {
        print(msg, params);
    }
}

const TestSuiteError = error{
    Fail,
};

const CommandType = enum {
    AssertReturn,
    AssertTrap,
};

const Invocation = struct {
    module: []const u8,
    field: []const u8,
    args: std.ArrayList(Val),

    fn parse(json_action: *std.json.Value, fallback_module: []const u8, allocator: std.mem.Allocator) !Invocation {
        const json_field = json_action.Object.getPtr("field").?;

        const json_args_or_null = json_action.Object.getPtr("args");
        var args = std.ArrayList(Val).init(allocator);
        if (json_args_or_null) |json_args| {
            for (json_args.Array.items) |item| {
                var val: Val = try parseVal(item.Object);
                try args.append(val);
            }
        }

        return Invocation{
            .module = fallback_module,
            .field = try allocator.dupe(u8, json_field.String),
            .args = args,
        };
    }
};

const CommandAssertReturn = struct {
    invocation: Invocation,
    expected_returns: ?std.ArrayList(Val),
};

const CommandAssertTrap = struct {
    invocation: Invocation,
    expected_error: []const u8,
};

// const CommandAssertInvalid = struct {
//     invocation: Invocation,
//     expected_error: []const u8,
// };

const Command = union(CommandType) {
    AssertReturn: CommandAssertReturn,
    AssertTrap: CommandAssertTrap,

    fn getModule(self: @This()) []const u8 {
        return switch (self) {
            .AssertReturn => |c| c.invocation.module,
            .AssertTrap => |c| c.invocation.module,
        };
    }
};

fn strcmp(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn parseVal(obj: std.json.ObjectMap) !Val {
    const json_type = obj.get("type").?;
    const json_value = obj.get("value").?;

    if (strcmp("i32", json_type.String)) {
        const int = std.fmt.parseInt(i32, json_value.String, 10) catch @bitCast(i32, try std.fmt.parseInt(u32, json_value.String, 10));
        return Val{ .I32 = int };
    } else if (strcmp("i64", json_type.String)) {
        const int = std.fmt.parseInt(i64, json_value.String, 10) catch @bitCast(i64, try std.fmt.parseInt(u64, json_value.String, 10));
        return Val{ .I64 = int };
    } else if (strcmp("f32", json_type.String)) {
        var float: f32 = undefined;
        if (std.mem.startsWith(u8, json_value.String, "nan:")) {
            float = std.math.nan_f32; // don't differentiate between arithmetic/canonical nan
        } else {
            const int = try std.fmt.parseInt(u32, json_value.String, 10);
            float = @bitCast(f32, int);
        }
        return Val{ .F32 = float };
    } else if (strcmp("f64", json_type.String)) {
        var float: f64 = undefined;
        if (std.mem.startsWith(u8, json_value.String, "nan:")) {
            float = std.math.nan_f64; // don't differentiate between arithmetic/canonical nan
        } else {
            const int = try std.fmt.parseInt(u64, json_value.String, 10);
            float = @bitCast(f64, int);
        }
        return Val{ .F64 = float };
    } else if (strcmp("externref", json_type.String)) {
        const int = try std.fmt.parseInt(u32, json_value.String, 10);
        return Val{ .ExternRef = int };
    } else {
        print("Failed to parse value of type '{s}' with value '{s}'\n", .{ json_type.String, json_value.String });
    }

    unreachable;
}

fn error_to_text(err: anyerror) []const u8 {
    return switch (err) {
        wasm.TrapError.TrapIntegerDivisionByZero => "integer divide by zero",
        wasm.TrapError.TrapIntegerOverflow => "integer overflow",
        wasm.TrapError.TrapInvalidIntegerConversion => "invalid conversion to integer",
        wasm.TrapError.TrapOutOfBoundsMemoryAccess => "out of bounds memory access",
        wasm.TrapError.TrapUndefinedElement => "undefined element",
        wasm.TrapError.TrapUnreachable => "unreachable",
        wasm.AssertError.AssertTypeMismatch => "type mismatch",
        wasm.AssertError.AssertUnknownMemory => "unknown memory",
        else => {
            std.debug.print("error_to_text unknown err: {}\n", .{err});
            unreachable;
        },
    };
}

fn parseCommands(json_path: []const u8, allocator: std.mem.Allocator) !std.ArrayList(Command) {
    // print("json_path: {s}\n", .{json_path});
    var json_data = try std.fs.cwd().readFileAlloc(allocator, json_path, 1024 * 1024 * 8);
    var parser = std.json.Parser.init(allocator, false);
    var tree = try parser.parse(json_data);

    var fallback_module: []const u8 = "";

    var commands = std.ArrayList(Command).init(allocator);

    const json_commands = tree.root.Object.getPtr("commands").?;
    for (json_commands.Array.items) |json_command| {
        const json_command_type = json_command.Object.getPtr("type").?;

        if (strcmp("module", json_command_type.String)) {
            var fallback = json_command.Object.getPtr("filename").?;
            fallback_module = try allocator.dupe(u8, fallback.String);
        } else if (strcmp("assert_return", json_command_type.String) or strcmp("action", json_command_type.String)) {
            const json_action = json_command.Object.getPtr("action").?;

            var invocation = try Invocation.parse(json_action, fallback_module, allocator);

            var expected_returns_or_null: ?std.ArrayList(Val) = null;
            const json_expected_or_null = json_command.Object.getPtr("expected");
            if (json_expected_or_null) |json_expected| {
                var expected_returns = std.ArrayList(Val).init(allocator);
                for (json_expected.Array.items) |item| {
                    try expected_returns.append(try parseVal(item.Object));
                }
                expected_returns_or_null = expected_returns;
            }

            var command = Command{ .AssertReturn = CommandAssertReturn{
                .invocation = invocation,
                .expected_returns = expected_returns_or_null,
            } };
            try commands.append(command);
        } else if (strcmp("assert_trap", json_command_type.String)) {
            const json_action = json_command.Object.getPtr("action").?;

            var invocation = try Invocation.parse(json_action, fallback_module, allocator);

            const json_text = json_command.Object.getPtr("text").?;

            var command = Command{ .AssertTrap = CommandAssertTrap{
                .invocation = invocation,
                .expected_error = try allocator.dupe(u8, json_text.String),
            } };
            try commands.append(command);
        } else if (strcmp("assert_invalid", json_command_type.String)) {
            // const json_filename = json_command.Object.get("filename").?;
            // const json_expected = json_command.Object.get("text").?;

            // var expected_error: ?anyerror = null;
            // const json_text_or_null = json_command.Object.get("text");
            // if (json_text_or_null) |text| {
            //     expected_error = error_from_text(text.String);
            // }

            // var command = Command{
            //     .AssertInvalid = CommandAssertInvalid {
            //         .module = try std.mem.dupe(allocator, u8, json_filename.String),
            //         .expected = try std.mem.dupe(allocator, u8, json_expected.String),
            //     },
            // };
            // try commands.append(command);
            log_verbose("Skipping assert_invalid test...\n", .{});
        } else if (strcmp("assert_malformed", json_command_type.String)) {
            // we will never test these since we aren't going to generate wasm from a wast
        } else {
            print("unknown command type: {s}\n", .{json_command_type.String});
            unreachable;
        }
    }

    return commands;
}

const Module = struct {
    def: wasm.ModuleDefinition,
    inst: wasm.ModuleInstance,
};

const TestOpts = struct {
    suite_filter_or_null: ?[]const u8 = null,
    test_filter_or_null: ?[]const u8 = null,
    command_filter_or_null: ?[]const u8 = null,
    module_filter_or_null: ?[]const u8 = null,
};

fn run(suite_path: []const u8, opts: *const TestOpts) !void {
    var did_fail_any_test: bool = false;

    var arena_commands = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_commands.deinit();

    var commands: std.ArrayList(Command) = try parseCommands(suite_path, arena_commands.child_allocator);

    const suite_dir = std.fs.path.dirname(suite_path).?;

    var name_to_module = std.StringHashMap(Module).init(std.testing.allocator);
    defer name_to_module.deinit();

    for (commands.items) |*command| {
        var module_name = command.getModule();
        if (opts.module_filter_or_null) |filter| {
            if (strcmp(filter, module_name) == false) {
                continue;
            }
        }

        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var module_or_null: ?*Module = name_to_module.getPtr(module_name);

        if (module_or_null == null) {
            var module_path = try std.fs.path.join(arena_commands.child_allocator, &[_][]const u8{ suite_dir, module_name });
            var cwd = std.fs.cwd();
            var module_data = try cwd.readFileAlloc(arena_commands.child_allocator, module_path, 1024 * 1024 * 8);
            // wasm.printBytecode("module data", module_data);

            var imports = wasm.PackageImports{
                .imports = std.ArrayList(wasm.ModuleImports).init(arena_commands.child_allocator),
            };
            defer imports.imports.deinit();

            var def = try wasm.ModuleDefinition.init(module_data, arena_commands.child_allocator);
            var inst = try wasm.ModuleInstance.init(&def, &imports, arena_commands.child_allocator);

            var module = Module{
                .def = def,
                .inst = inst,
            };
            var entry = try name_to_module.getOrPutValue(module_name, module);
            module_or_null = entry.value_ptr;
        }

        var module = module_or_null.?;

        // print("module_path: {s}\n", .{module_path});

        switch (command.*) {
            .AssertReturn => |c| {
                if (opts.command_filter_or_null) |filter| {
                    if (strcmp("assert_return", filter) == false) {
                        continue;
                    }
                }

                if (opts.test_filter_or_null) |filter| {
                    if (strcmp(filter, c.invocation.field) == false) {
                        log_verbose("assert_return: skipping {s}:{s}\n", .{ module_name, c.invocation.field });
                        continue;
                    }
                }

                const num_expected_returns = if (c.expected_returns) |returns| returns.items.len else 0;
                var returns_placeholder: [8]Val = undefined;
                var returns = returns_placeholder[0..num_expected_returns];

                log_verbose("assert_return: {s}:{s}({s})\n", .{ module_name, c.invocation.field, c.invocation.args.items });

                var invoke_succeeded = true;
                // try module.inst.invoke(c.field, c.args.items, returns);
                module.inst.invoke(c.invocation.field, c.invocation.args.items, returns) catch |e| {
                    if (!g_verbose_logging) {
                        print("assert_return: {s}:{s}({s})\n", .{ module_name, c.invocation.field, c.invocation.args.items });
                    }
                    print("\tFail with error: {}\n", .{e});
                    invoke_succeeded = false;
                };

                if (invoke_succeeded) {
                    if (c.expected_returns) |expected| {
                        for (returns) |r, i| {
                            var pass = false;

                            if (std.meta.activeTag(expected.items[i]) == .F32 and std.math.isNan(expected.items[i].F32)) {
                                pass = std.meta.activeTag(r) == .F32 and std.math.isNan(r.F32);
                            } else if (std.meta.activeTag(expected.items[i]) == .F64 and std.math.isNan(expected.items[i].F64)) {
                                pass = std.meta.activeTag(r) == .F64 and std.math.isNan(r.F64);
                            } else {
                                pass = std.meta.eql(r, expected.items[i]);
                                if (!pass) {
                                    // std.debug.print(">>>>>>>>>>>> fail. expected: {e:0.16}, actual: {e:0.16}\n", .{ expected.items[i].F32, r.F32 });
                                }
                            }

                            if (pass == false) {
                                if (!g_verbose_logging) {
                                    print("assert_return: {s}:{s}({s})\n", .{ module_name, c.invocation.field, c.invocation.args.items });
                                }
                                print("\tFail on return {}/{}. Expected: {}, Actual: {}\n", .{ i + 1, returns.len, expected.items[i], r });
                                invoke_succeeded = false;
                            }
                        }
                    }

                    if (invoke_succeeded) {
                        log_verbose("\tSuccess!\n", .{});
                    }
                }
            },
            .AssertTrap => |c| {
                if (opts.command_filter_or_null) |filter| {
                    if (strcmp("assert_trap", filter) == false) {
                        continue;
                    }
                }

                if (opts.test_filter_or_null) |filter| {
                    if (strcmp(filter, c.invocation.field) == false) {
                        log_verbose("assert_return: skipping {s}:{s}\n", .{ module_name, c.invocation.field });
                        continue;
                    }
                }

                log_verbose("assert_trap: {s}:{s}({s})\n", .{ module_name, c.invocation.field, c.invocation.args.items });

                var returns_placeholder: [8]Val = undefined;
                var returns = returns_placeholder[0..];

                var invoke_failed = false;
                var invoke_failed_with_correct_trap = false;
                var trap_string: ?[]const u8 = null;
                module.inst.invoke(c.invocation.field, c.invocation.args.items, returns) catch |e| {
                    invoke_failed = true;

                    trap_string = error_to_text(e);

                    if (strcmp(trap_string.?, c.expected_error)) {
                        invoke_failed_with_correct_trap = true;
                    }
                };

                if (invoke_failed and invoke_failed_with_correct_trap) {
                    log_verbose("\tSuccess!\n", .{});
                } else {
                    if (!g_verbose_logging) {
                        print("assert_trap: {s}:{s}({s})\n", .{ module_name, c.invocation.field, c.invocation.args.items });
                    }
                    // print("assert_trap: {s}:{s}({s}):\n", .{ module_name, c.invocation.field, c.invocation.args.items });
                    if (invoke_failed_with_correct_trap == false) {
                        print("\tInvoke trapped, but got error '{s}'' instead of expected '{s}':\n", .{ trap_string.?, c.expected_error });
                    } else {
                        print("\tInvoke succeeded instead of trapping on expected {s}:\n", .{c.expected_error});
                    }
                }

                // print("skipping trap\n", .{});
            },
            // .AssertInvalid => {
            //     // var returns: [8]Val = undefined;
            //     // try module.callFunc(c.field, c.args.items, &returns[0..c.expected.items.len]);
            // },
        }
    }

    if (did_fail_any_test) {
        return TestSuiteError.Fail;
    }
}

pub fn main() !void {
    var allocator = std.testing.allocator;

    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var opts = TestOpts{};

    var args_index: u32 = 1; // skip program name
    while (args_index < args.len) : (args_index += 1) {
        var arg = args[args_index];
        if (strcmp("--suite", arg)) {
            args_index += 1;
            opts.suite_filter_or_null = args[args_index];
            print("found suite filter: {s}\n", .{opts.suite_filter_or_null.?});
        } else if (strcmp("--test", arg)) {
            args_index += 1;
            opts.test_filter_or_null = args[args_index];
            print("found test filter: {s}\n", .{opts.test_filter_or_null.?});
        } else if (strcmp("--command", arg)) {
            args_index += 1;
            opts.command_filter_or_null = args[args_index];
            print("found command filter: {s}\n", .{opts.command_filter_or_null.?});
        } else if (strcmp("--module", arg)) {
            args_index += 1;
            opts.module_filter_or_null = args[args_index];
            print("found module filter: {s}\n", .{opts.module_filter_or_null.?});
        } else if (strcmp("--verbose", arg) or strcmp("-v", arg)) {
            g_verbose_logging = true;
            print("verbose logging: on\n", .{});
        }
    }

    const all_suites = [_][]const u8{
        "address",
        "align",
        "binary",
        "binary-leb128",
        "block",
        "br",
        "br_if",
        "br_table",
        // "bulk",
        // "call",
        // "call_indirect",
        "comments",
        "const",
        "conversions",
        "custom",
        // "data",
        // "elem",
        "endianness",
        // "exports",
        "f32",
        "f32_bitwise",
        "f32_cmp",
        "f64",
        "f64_bitwise",
        "f64_cmp",
        // "fac",
        // "float_exprs",
        // "float_literals",
        // "float_memory",
        // "float_misc",
        "forward",
        // "func",
        // "func_ptrs",
        // "global",
        "i32",
        "i64",
        "if",
        // "imports",
        "inline-module",
        "int_exprs",
        "int_literals",
        // "labels",
        // "left-to-right",
        // "linking",
        "load",
        // "local_get",
        // "local_set",
        // "local_tee",
        // "loop",
        "memory",
        // "memory_copy",
        // "memory_fill",
        // "memory_grow",
        "memory_init",
        // "memory_redundancy",
        "memory_size",
        "memory_trap",
        // "names",
        "nop",
        // "ref_func",
        // "ref_is_null",
        // "ref_null",
        // "return",
        // "select",
        // "skip-stack-guard-page",
        // "stack",
        // "start",
        "store",
        // "switch",
        //"table",
        //"table-sub",
        //"table_copy",
        //"table_fill",
        //"table_get",
        //"table_grow",
        //"table_init",
        //"table_set",
        //"table_size",
        "token",
        "traps",
        "type",
        "unreachable",
        // "unreached-invalid",
        // "unreached-valid",
        "unwind",
        "utf8-custom-section-id",
        "utf8-import-field",
        "utf8-import-module",
        "utf8-invalid-encoding",
    };

    for (all_suites) |suite| {
        if (opts.suite_filter_or_null) |filter| {
            if (strcmp(filter, suite) == false) {
                continue;
            }
        }

        log_verbose("Running test suite: {s}\n", .{suite});

        var suite_path_no_extension: []const u8 = try std.fs.path.join(allocator, &[_][]const u8{ "test", "wasm", suite, suite });
        defer allocator.free(suite_path_no_extension);

        var suite_path = try std.mem.join(allocator, "", &[_][]const u8{ suite_path_no_extension, ".json" });
        defer allocator.free(suite_path);

        try run(suite_path, &opts);
    }
}
