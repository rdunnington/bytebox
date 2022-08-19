const std = @import("std");
const testing = std.testing;
const wasm = @import("vm.zig");
const ValType = wasm.ValType;
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
    DecodeModule,
    Register,
    AssertReturn,
    AssertTrap,
    AssertMalformed,
    AssertInvalid,
    AssertUnlinkable,
    AssertUninstantiable,
};

const ActionType = enum {
    Invocation,
    Get,
};

const Action = struct {
    type: ActionType,
    module: []const u8,
    field: []const u8,
    args: std.ArrayList(Val),
};

const BadModuleError = struct {
    module: []const u8,
    expected_error: []const u8,
};

const CommandDecodeModule = struct {
    module_filename: []const u8,
    module_name: []const u8,
};

const CommandRegister = struct {
    module_filename: []const u8,
    module_name: []const u8,
    import_name: []const u8,
};

const CommandAssertReturn = struct {
    action: Action,
    expected_returns: ?std.ArrayList(Val),
};

const CommandAssertTrap = struct {
    action: Action,
    expected_error: []const u8,
};

const CommandAssertMalformed = struct {
    err: BadModuleError,
};

const CommandAssertInvalid = struct {
    err: BadModuleError,
};

const CommandAssertUnlinkable = struct {
    err: BadModuleError,
};

const CommandAssertUninstantiable = struct {
    err: BadModuleError,
};

const Command = union(CommandType) {
    DecodeModule: CommandDecodeModule,
    Register: CommandRegister,
    AssertReturn: CommandAssertReturn,
    AssertTrap: CommandAssertTrap,
    AssertMalformed: CommandAssertMalformed,
    AssertInvalid: CommandAssertInvalid,
    AssertUnlinkable: CommandAssertUnlinkable,
    AssertUninstantiable: CommandAssertUninstantiable,

    fn getCommandName(self: *const Command) []const u8 {
        return switch (self.*) {
            .DecodeModule => "decode_module",
            .Register => "register",
            .AssertReturn => "assert_return",
            .AssertTrap => "assert_trap",
            .AssertMalformed => "assert_malformed",
            .AssertInvalid => "assert_invalid",
            .AssertUnlinkable => "assert_unlinkable",
            .AssertUninstantiable => "assert_uninstantiable",
        };
    }

    fn getModuleFilename(self: *const Command) []const u8 {
        return switch (self.*) {
            .DecodeModule => |c| c.module_filename,
            .Register => |c| c.module_filename,
            else => return getModuleName(self),
        };
    }

    fn getModuleName(self: *const Command) []const u8 {
        return switch (self.*) {
            .DecodeModule => |c| c.module_name,
            .Register => |c| c.module_name,
            .AssertReturn => |c| c.action.module,
            .AssertTrap => |c| c.action.module,
            .AssertMalformed => |c| c.err.module,
            .AssertInvalid => |c| c.err.module,
            .AssertUnlinkable => |c| c.err.module,
            .AssertUninstantiable => |c| c.err.module,
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
        if (strcmp("null", json_value.String)) {
            return Val.nullRef(ValType.ExternRef);
        } else {
            const int = try std.fmt.parseInt(u32, json_value.String, 10);
            return Val{ .ExternRef = int };
        }
    } else if (strcmp("funcref", json_type.String)) {
        if (strcmp("null", json_value.String)) {
            return Val.nullRef(ValType.FuncRef);
        } else {
            const int = try std.fmt.parseInt(u32, json_value.String, 10);
            return Val{ .FuncRef = .{ .index = int, .module_instance = null } };
        }
    } else {
        print("Failed to parse value of type '{s}' with value '{s}'\n", .{ json_type.String, json_value.String });
    }

    unreachable;
}

fn isSameError(err: anyerror, err_string: []const u8) bool {
    return switch (err) {
        wasm.MalformedError.MalformedMagicSignature => strcmp(err_string, "magic header not detected"),
        wasm.MalformedError.MalformedUnexpectedEnd => strcmp(err_string, "unexpected end") or
            strcmp(err_string, "unexpected end of section or function") or
            strcmp(err_string, "length out of bounds"),
        wasm.MalformedError.MalformedUnsupportedWasmVersion => strcmp(err_string, "unknown binary version"),
        wasm.MalformedError.MalformedSectionId => strcmp(err_string, "malformed section id"),
        wasm.MalformedError.MalformedTypeSentinel => strcmp(err_string, "integer representation too long") or strcmp(err_string, "integer too large"),
        wasm.MalformedError.MalformedLEB128 => strcmp(err_string, "integer representation too long") or strcmp(err_string, "integer too large"),
        wasm.MalformedError.MalformedMissingZeroByte => strcmp(err_string, "zero byte expected"),
        wasm.MalformedError.MalformedTooManyLocals => strcmp(err_string, "too many locals"),
        wasm.MalformedError.MalformedFunctionCodeSectionMismatch => strcmp(err_string, "function and code section have inconsistent lengths"),
        wasm.MalformedError.MalformedMissingDataCountSection => strcmp(err_string, "data count section required"),
        wasm.MalformedError.MalformedDataCountMismatch => strcmp(err_string, "data count and data section have inconsistent lengths"),
        wasm.MalformedError.MalformedDataType => strcmp(err_string, "integer representation too long") or strcmp(err_string, "integer too large"),
        wasm.MalformedError.MalformedIllegalOpcode => strcmp(err_string, "illegal opcode") or strcmp(err_string, "integer representation too long"),
        wasm.MalformedError.MalformedReferenceType => strcmp(err_string, "malformed reference type"),
        wasm.MalformedError.MalformedSectionSizeMismatch => strcmp(err_string, "section size mismatch") or
            strcmp(err_string, "malformed section id") or
            strcmp(err_string, "function and code section have inconsistent lengths"), // this one is a bit of a hack to resolve custom.8.wasm
        wasm.MalformedError.MalformedInvalidImport => strcmp(err_string, "malformed import kind"),
        wasm.MalformedError.MalformedLimits => strcmp(err_string, "integer too large") or strcmp(err_string, "integer representation too long"),
        wasm.MalformedError.MalformedMultipleStartSections => strcmp(err_string, "multiple start sections") or
            strcmp(err_string, "unexpected content after last section"),
        wasm.MalformedError.MalformedElementType => strcmp(err_string, "integer representation too long") or strcmp(err_string, "integer too large"),
        wasm.MalformedError.MalformedUTF8Encoding => strcmp(err_string, "malformed UTF-8 encoding"),
        wasm.MalformedError.MalformedMutability => strcmp(err_string, "malformed mutability"),

        wasm.ValidationError.ValidationTypeMismatch => strcmp(err_string, "type mismatch"),
        wasm.ValidationError.ValidationUnknownTable => strcmp(err_string, "unknown table"),
        wasm.ValidationError.ValidationUnknownMemory => strcmp(err_string, "unknown memory"),
        wasm.ValidationError.ValidationUnknownData => strcmp(err_string, "unknown data"),

        wasm.UnlinkableError.UnlinkableUnknownImport => strcmp(err_string, "unknown import"),
        wasm.UnlinkableError.UnlinkableIncompatibleImportType => strcmp(err_string, "incompatible import type"),

        wasm.UninstantiableError.UninstantiableOutOfBoundsTableAccess => strcmp(err_string, "out of bounds table access"),
        wasm.UninstantiableError.UninstantiableOutOfBoundsMemoryAccess => strcmp(err_string, "out of bounds memory access"),

        wasm.TrapError.TrapIntegerDivisionByZero => strcmp(err_string, "integer divide by zero"),
        wasm.TrapError.TrapIntegerOverflow => strcmp(err_string, "integer overflow"),
        wasm.TrapError.TrapInvalidIntegerConversion => strcmp(err_string, "invalid conversion to integer"),
        wasm.TrapError.TrapOutOfBoundsMemoryAccess => strcmp(err_string, "out of bounds memory access"),
        wasm.TrapError.TrapUndefinedElement => strcmp(err_string, "undefined element"),
        wasm.TrapError.TrapUninitializedElement => strcmp(err_string, "uninitialized element"),
        wasm.TrapError.TrapOutOfBoundsTableAccess => strcmp(err_string, "out of bounds table access"),
        wasm.TrapError.TrapUnreachable => strcmp(err_string, "unreachable"),

        else => false,
    };
}

fn parseCommands(json_path: []const u8, allocator: std.mem.Allocator) !std.ArrayList(Command) {
    const Helpers = struct {
        fn parseAction(json_action: *std.json.Value, fallback_module: []const u8, _allocator: std.mem.Allocator) !Action {
            const json_type = json_action.Object.getPtr("type").?;
            var action_type: ActionType = undefined;
            if (strcmp("invoke", json_type.String)) {
                action_type = .Invocation;
            } else if (strcmp("get", json_type.String)) {
                action_type = .Get;
            } else {
                unreachable;
            }

            const json_field = json_action.Object.getPtr("field").?;

            const json_args_or_null = json_action.Object.getPtr("args");
            var args = std.ArrayList(Val).init(_allocator);
            if (json_args_or_null) |json_args| {
                for (json_args.Array.items) |item| {
                    var val: Val = try parseVal(item.Object);
                    try args.append(val);
                }
            }

            var module: []const u8 = fallback_module;
            const json_module_or_null = json_action.Object.getPtr("module");
            if (json_module_or_null) |json_module| {
                module = try _allocator.dupe(u8, json_module.String);
            }

            return Action{
                .type = action_type,
                .module = module,
                .field = try _allocator.dupe(u8, json_field.String),
                .args = args,
            };
        }

        fn parseBadModuleError(json_command: *const std.json.Value, _allocator: std.mem.Allocator) !BadModuleError {
            const json_filename = json_command.Object.get("filename").?;
            const json_expected = json_command.Object.get("text").?;

            return BadModuleError{
                .module = try _allocator.dupe(u8, json_filename.String),
                .expected_error = try _allocator.dupe(u8, json_expected.String),
            };
        }
    };

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
            const json_filename = json_command.Object.getPtr("filename").?;
            var filename: []const u8 = try allocator.dupe(u8, json_filename.String);
            fallback_module = filename;

            var name = filename;
            if (json_command.Object.getPtr("name")) |json_module_name| {
                name = try allocator.dupe(u8, json_module_name.String);
            }

            var command = Command{
                .DecodeModule = CommandDecodeModule{
                    .module_filename = filename,
                    .module_name = name,
                },
            };
            try commands.append(command);
        } else if (strcmp("register", json_command_type.String)) {
            const json_as = json_command.Object.getPtr("as").?;
            var json_import_name: []const u8 = json_as.String;
            var json_module_name: []const u8 = fallback_module;
            if (json_command.Object.getPtr("name")) |json_name| {
                json_module_name = json_name.String;
            }

            // print("json_module_name: {s}, json_import_name: {s}\n", .{ json_module_name, json_import_name });

            var command = Command{
                .Register = CommandRegister{
                    .module_filename = try allocator.dupe(u8, fallback_module),
                    .module_name = try allocator.dupe(u8, json_module_name),
                    .import_name = try allocator.dupe(u8, json_import_name),
                },
            };
            try commands.append(command);
        } else if (strcmp("assert_return", json_command_type.String) or strcmp("action", json_command_type.String)) {
            const json_action = json_command.Object.getPtr("action").?;

            var action = try Helpers.parseAction(json_action, fallback_module, allocator);

            var expected_returns_or_null: ?std.ArrayList(Val) = null;
            const json_expected_or_null = json_command.Object.getPtr("expected");
            if (json_expected_or_null) |json_expected| {
                var expected_returns = std.ArrayList(Val).init(allocator);
                for (json_expected.Array.items) |item| {
                    try expected_returns.append(try parseVal(item.Object));
                }
                expected_returns_or_null = expected_returns;
            }

            var command = Command{
                .AssertReturn = CommandAssertReturn{
                    .action = action,
                    .expected_returns = expected_returns_or_null,
                },
            };
            try commands.append(command);
        } else if (strcmp("assert_trap", json_command_type.String)) {
            const json_action = json_command.Object.getPtr("action").?;

            var action = try Helpers.parseAction(json_action, fallback_module, allocator);

            const json_text = json_command.Object.getPtr("text").?;

            var command = Command{
                .AssertTrap = CommandAssertTrap{
                    .action = action,
                    .expected_error = try allocator.dupe(u8, json_text.String),
                },
            };
            try commands.append(command);
        } else if (strcmp("assert_malformed", json_command_type.String)) {
            var command = Command{
                .AssertMalformed = CommandAssertMalformed{
                    .err = try Helpers.parseBadModuleError(&json_command, allocator),
                },
            };
            if (std.mem.endsWith(u8, command.AssertMalformed.err.module, ".wasm")) {
                try commands.append(command);
            }
        } else if (strcmp("assert_invalid", json_command_type.String)) {
            var command = Command{
                .AssertInvalid = CommandAssertInvalid{
                    .err = try Helpers.parseBadModuleError(&json_command, allocator),
                },
            };
            try commands.append(command);
        } else if (strcmp("assert_unlinkable", json_command_type.String)) {
            var command = Command{
                .AssertUnlinkable = CommandAssertUnlinkable{
                    .err = try Helpers.parseBadModuleError(&json_command, allocator),
                },
            };
            try commands.append(command);
        } else if (strcmp("assert_uninstantiable", json_command_type.String)) {
            var command = Command{
                .AssertUninstantiable = CommandAssertUninstantiable{
                    .err = try Helpers.parseBadModuleError(&json_command, allocator),
                },
            };
            try commands.append(command);
        } else {
            print("unknown command type: {s}\n", .{json_command_type.String});
            unreachable;
        }
    }

    return commands;
}

const Module = struct {
    filename: []const u8 = "",
    def: ?wasm.ModuleDefinition = null,
    inst: ?wasm.ModuleInstance = null,
};

const TestOpts = struct {
    suite_filter_or_null: ?[]const u8 = null,
    test_filter_or_null: ?[]const u8 = null,
    command_filter_or_null: ?[]const u8 = null,
    module_filter_or_null: ?[]const u8 = null,
};

fn makeSpectestImports(allocator: std.mem.Allocator) !wasm.ModuleImports {
    const Functions = struct {
        fn printI32(_: ?*anyopaque, params: []const Val, returns: []Val) void {
            std.debug.assert(params.len == 1);
            std.debug.assert(returns.len == 0);
            std.debug.assert(std.meta.activeTag(params[0]) == ValType.I32);
            // std.debug.print("{}", .{params[0].I32});
        }

        fn printI64(_: ?*anyopaque, params: []const Val, returns: []Val) void {
            std.debug.assert(params.len == 1);
            std.debug.assert(returns.len == 0);
            std.debug.assert(std.meta.activeTag(params[0]) == ValType.I64);
            // std.debug.print("{}", .{params[0].I64});
        }

        fn printF32(_: ?*anyopaque, params: []const Val, returns: []Val) void {
            std.debug.assert(params.len == 1);
            std.debug.assert(returns.len == 0);
            std.debug.assert(std.meta.activeTag(params[0]) == ValType.F32);
            // std.debug.print("{}", .{params[0].F32});
        }

        fn printF64(_: ?*anyopaque, params: []const Val, returns: []Val) void {
            std.debug.assert(params.len == 1);
            std.debug.assert(returns.len == 0);
            std.debug.assert(std.meta.activeTag(params[0]) == ValType.F64);
            // std.debug.print("{}", .{params[0].F64});
        }

        fn printI32F32(_: ?*anyopaque, params: []const Val, returns: []Val) void {
            std.debug.assert(params.len == 2);
            std.debug.assert(returns.len == 0);
            std.debug.assert(std.meta.activeTag(params[0]) == ValType.I32);
            std.debug.assert(std.meta.activeTag(params[1]) == ValType.F32);
            // std.debug.print("{} {}", .{ params[0].I32, params[1].F32 });
        }

        fn printF64F64(_: ?*anyopaque, params: []const Val, returns: []Val) void {
            std.debug.assert(params.len == 2);
            std.debug.assert(returns.len == 0);
            std.debug.assert(std.meta.activeTag(params[0]) == ValType.F64);
            std.debug.assert(std.meta.activeTag(params[1]) == ValType.F64);
            // std.debug.print("{} {}", .{ params[0].F64, params[1].F64 });
        }

        fn print(_: ?*anyopaque, params: []const Val, returns: []Val) void {
            std.debug.assert(params.len == 0);
            std.debug.assert(returns.len == 0);
            // std.debug.print("\n", .{});
        }
    };

    const Helpers = struct {
        fn addGlobal(imports: *wasm.ModuleImports, _allocator: std.mem.Allocator, mut: wasm.GlobalMut, comptime T: type, value: T, name: []const u8) !void {
            const val: Val = switch (T) {
                i32 => Val{ .I32 = value },
                i64 => Val{ .I64 = value },
                f32 => Val{ .F32 = value },
                f64 => Val{ .F64 = value },
                else => unreachable,
            };
            var global = try _allocator.create(wasm.GlobalInstance);
            global.* = wasm.GlobalInstance{
                .mut = mut,
                .value = val,
            };
            try imports.globals.append(wasm.GlobalImport{
                .name = try _allocator.dupe(u8, name),
                .data = .{ .Host = global },
            });
        }
    };
    var imports: wasm.ModuleImports = try wasm.ModuleImports.init("spectest", null, allocator);

    const no_returns = &[0]ValType{};

    try imports.addHostFunction("print_i32", null, &[_]ValType{.I32}, no_returns, Functions.printI32);
    try imports.addHostFunction("print_i64", null, &[_]ValType{.I64}, no_returns, Functions.printI64);
    try imports.addHostFunction("print_f32", null, &[_]ValType{.F32}, no_returns, Functions.printF32);
    try imports.addHostFunction("print_f64", null, &[_]ValType{.F64}, no_returns, Functions.printF64);
    try imports.addHostFunction("print_i32_f32", null, &[_]ValType{ .I32, .F32 }, no_returns, Functions.printI32F32);
    try imports.addHostFunction("print_f64_f64", null, &[_]ValType{ .F64, .F64 }, no_returns, Functions.printF64F64);
    try imports.addHostFunction("print_f64_f64", null, &[_]ValType{ .F64, .F64 }, no_returns, Functions.printF64F64);
    try imports.addHostFunction("print", null, &[_]ValType{}, no_returns, Functions.print);

    const TableInstance = wasm.TableInstance;

    var table = try allocator.create(TableInstance);
    table.* = try TableInstance.init(ValType.FuncRef, wasm.Limits{ .min = 10, .max = 20 }, allocator);
    try imports.tables.append(wasm.TableImport{
        .name = try allocator.dupe(u8, "table"),
        .data = .{ .Host = table },
    });

    const MemoryInstance = wasm.MemoryInstance;

    var memory = try allocator.create(MemoryInstance);
    memory.* = MemoryInstance.init(wasm.Limits{
        .min = 1,
        .max = 2,
    });
    _ = memory.grow(1);
    try imports.memories.append(wasm.MemoryImport{
        .name = try allocator.dupe(u8, "memory"),
        .data = .{ .Host = memory },
    });

    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Immutable, i32, 666, "global_i32");
    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Immutable, i64, 666, "global_i64");
    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Immutable, f32, 666.6, "global_f32");
    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Immutable, f64, 666.6, "global_f64");
    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Immutable, i32, 0, "global-i32");
    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Immutable, f32, 0, "global-f32");
    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Mutable, i32, 0, "global-mut-i32");
    try Helpers.addGlobal(&imports, allocator, wasm.GlobalMut.Mutable, i64, 0, "global-mut-i64");

    return imports;
}

fn run(suite_path: []const u8, opts: *const TestOpts) !void {
    var did_fail_any_test: bool = false;

    var arena_commands = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_commands.deinit();

    var scratch_allocator = arena_commands.allocator();

    var commands: std.ArrayList(Command) = try parseCommands(suite_path, scratch_allocator);

    const suite_dir = std.fs.path.dirname(suite_path).?;

    var name_to_module = std.StringHashMap(Module).init(std.testing.allocator);
    defer name_to_module.deinit();

    // this should be enough to avoid resizing, just bump it up if it's not
    // note that module instance uses the pointer to the stored struct so it's important that the stored instances never move
    name_to_module.ensureTotalCapacity(256) catch unreachable;

    // NOTE this shares the same copies of the import arrays, since the modules must share instances
    var imports = std.ArrayList(wasm.ModuleImports).init(std.testing.allocator);

    try imports.append(try makeSpectestImports(std.testing.allocator));

    for (commands.items) |*command| {
        switch (command.*) {
            .AssertInvalid => |c| {
                log_verbose("Skipping assert_invalid: {s}\n", .{c.err.module});
                continue;
            },
            else => {},
        }

        const module_filename = command.getModuleFilename();
        const module_name = command.getModuleName();
        if (opts.module_filter_or_null) |filter| {
            if (strcmp(filter, module_filename) == false) {
                continue;
            }
        }
        // std.debug.print("looking for (name/filename) {s}:{s}\n", .{ module_name, module_filename });

        var entry = name_to_module.getOrPutAssumeCapacity(module_name);
        var module: *Module = entry.value_ptr;
        if (entry.found_existing == false) {
            module.* = Module{};
        }

        switch (command.*) {
            .AssertReturn => {},
            .AssertTrap => {},
            else => log_verbose("{s}: {s}|{s}\n", .{ command.getCommandName(), module_name, module_filename }),
        }

        switch (command.*) {
            .Register => |c| {
                if (module.inst == null) {
                    print(
                        "Register: module instance {s}|{s} was not found in the cache by the name '{s}'. Is the wast malformed?\n",
                        .{ c.module_name, module_filename, module_name },
                    );
                    continue;
                }

                log_verbose("\tSetting export module name to {s}\n", .{c.import_name});

                var module_imports: wasm.ModuleImports = try (module.inst.?).exports(c.import_name);
                try imports.append(module_imports);
                continue;
            },
            else => {},
        }

        if (module.inst == null) {
            var module_path = try std.fs.path.join(scratch_allocator, &[_][]const u8{ suite_dir, module_filename });
            var cwd = std.fs.cwd();
            var module_data = try cwd.readFileAlloc(scratch_allocator, module_path, 1024 * 1024 * 8);

            var decode_expected_error: ?[]const u8 = null;
            switch (command.*) {
                .AssertMalformed => |c| {
                    decode_expected_error = c.err.expected_error;
                },
                else => {},
            }

            module.filename = try scratch_allocator.dupe(u8, module_filename);

            module.def = wasm.ModuleDefinition.init(module_data, scratch_allocator) catch |e| {
                if (decode_expected_error) |expected_str| {
                    if (isSameError(e, expected_str)) {
                        log_verbose("\tSuccess!\n", .{});
                    } else {
                        if (!g_verbose_logging) {
                            print("{s}: {s}\n", .{ command.getCommandName(), module.filename });
                        }
                        print("\tFail: decode failed with error {}, but expected '{s}'\n", .{ e, expected_str });
                    }
                } else {
                    if (!g_verbose_logging) {
                        print("{s}: {s}\n", .{ command.getCommandName(), module.filename });
                    }
                    print("\tDecode failed with error: {}\n", .{e});
                }
                continue;
            };

            if (decode_expected_error) |expected| {
                if (!g_verbose_logging) {
                    print("{s}: {s}\n", .{ command.getCommandName(), module.filename });
                }
                print("\tFail: decode succeeded, but it should have failed with error '{s}'\n", .{expected});
            }

            var instantiate_expected_error: ?[]const u8 = null;
            switch (command.*) {
                .AssertUninstantiable => |c| {
                    instantiate_expected_error = c.err.expected_error;
                },
                .AssertUnlinkable => |c| {
                    instantiate_expected_error = c.err.expected_error;
                },
                else => {},
            }

            module.inst = wasm.ModuleInstance.init(&module.def.?, scratch_allocator);
            (module.inst.?).instantiate(imports.items) catch |e| {
                if (instantiate_expected_error) |expected_str| {
                    if (isSameError(e, expected_str)) {
                        log_verbose("\tSuccess!\n", .{});
                    } else {
                        if (!g_verbose_logging) {
                            print("{s}: {s}\n", .{ command.getCommandName(), module.filename });
                        }
                        print("\tFail: instantiate failed with error {}, but expected '{s}'\n", .{ e, expected_str });
                    }
                } else {
                    if (!g_verbose_logging) {
                        print("{s}: {s}\n", .{ command.getCommandName(), module.filename });
                    }
                    print("\tInstantiate failed with error: {}\n", .{e});
                }
                continue;
            };

            if (instantiate_expected_error) |expected| {
                if (!g_verbose_logging) {
                    print("{s}: {s}\n", .{ command.getCommandName(), module.filename });
                }
                print("\tFail: instantiate succeeded, but it should have failed with error '{s}'\n", .{expected});
            }
        }

        // print("module_path: {s}\n", .{module_path});

        switch (command.*) {
            .AssertReturn => |c| {
                if (opts.command_filter_or_null) |filter| {
                    if (strcmp("assert_return", filter) == false) {
                        continue;
                    }
                }

                if (opts.test_filter_or_null) |filter| {
                    if (strcmp(filter, c.action.field) == false) {
                        log_verbose("\tskipped...\n", .{});
                        continue;
                    }
                }

                const num_expected_returns = if (c.expected_returns) |returns| returns.items.len else 0;
                var returns_placeholder: [8]Val = undefined;
                var returns = returns_placeholder[0..num_expected_returns];

                log_verbose("assert_return: {s}:{s}({s})\n", .{ module.filename, c.action.field, c.action.args.items });

                var action_succeeded = true;
                switch (c.action.type) {
                    .Invocation => {
                        (module.inst.?).invoke(c.action.field, c.action.args.items, returns) catch |e| {
                            if (!g_verbose_logging) {
                                print("assert_return: {s}:{s}({s})\n", .{ module.filename, c.action.field, c.action.args.items });
                            }
                            print("\tInvoke fail with error: {}\n", .{e});
                            action_succeeded = false;
                        };
                    },
                    .Get => {
                        var val_or_error: anyerror!wasm.Val = (module.inst.?).getGlobal(c.action.field);
                        if (val_or_error) |value| {
                            returns[0] = value;
                        } else |e| {
                            if (!g_verbose_logging) {
                                print("assert_return: {s}:{s}({s})\n", .{ module.filename, c.action.field, c.action.args.items });
                            }
                            print("\tGet fail with error: {}\n", .{e});
                            action_succeeded = false;
                        }
                    },
                }

                if (action_succeeded) {
                    if (c.expected_returns) |expected| {
                        for (returns) |r, i| {
                            var pass = false;

                            if (std.meta.activeTag(expected.items[i]) == .F32 and std.math.isNan(expected.items[i].F32)) {
                                pass = std.meta.activeTag(r) == .F32 and std.math.isNan(r.F32);
                            } else if (std.meta.activeTag(expected.items[i]) == .F64 and std.math.isNan(expected.items[i].F64)) {
                                pass = std.meta.activeTag(r) == .F64 and std.math.isNan(r.F64);
                            } else {
                                pass = std.meta.eql(r, expected.items[i]);
                            }

                            if (pass == false) {
                                if (!g_verbose_logging) {
                                    print("assert_return: {s}:{s}({s})\n", .{ module.filename, c.action.field, c.action.args.items });
                                }
                                print("\tFail on return {}/{}. Expected: {}, Actual: {}\n", .{ i + 1, returns.len, expected.items[i], r });
                                action_succeeded = false;
                            }
                        }
                    }

                    if (action_succeeded) {
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
                    if (strcmp(filter, c.action.field) == false) {
                        log_verbose("assert_return: skipping {s}:{s}\n", .{ module.filename, c.action.field });
                        continue;
                    }
                }

                log_verbose("assert_trap: {s}:{s}({s})\n", .{ module.filename, c.action.field, c.action.args.items });

                var returns_placeholder: [8]Val = undefined;
                var returns = returns_placeholder[0..];

                var action_failed = false;
                var action_failed_with_correct_trap = false;
                var caught_error: ?anyerror = null;

                switch (c.action.type) {
                    .Invocation => {
                        (module.inst.?).invoke(c.action.field, c.action.args.items, returns) catch |e| {
                            action_failed = true;
                            caught_error = e;

                            if (isSameError(e, c.expected_error)) {
                                action_failed_with_correct_trap = true;
                            }
                        };
                    },
                    .Get => {
                        var val_or_error: anyerror!wasm.Val = (module.inst.?).getGlobal(c.action.field);
                        if (val_or_error) |value| {
                            returns[0] = value;
                        } else |e| {
                            action_failed = true;
                            caught_error = e;

                            if (isSameError(e, c.expected_error)) {
                                action_failed_with_correct_trap = true;
                            }
                        }
                    },
                }

                if (action_failed and action_failed_with_correct_trap) {
                    log_verbose("\tSuccess!\n", .{});
                } else {
                    if (!g_verbose_logging) {
                        print("assert_trap: {s}:{s}({s})\n", .{ module.filename, c.action.field, c.action.args.items });
                    }
                    if (action_failed_with_correct_trap == false) {
                        print("\tInvoke trapped, but got error '{s}'' instead of expected '{s}':\n", .{ caught_error.?, c.expected_error });
                    } else {
                        print("\tInvoke succeeded instead of trapping on expected {s}:\n", .{c.expected_error});
                    }
                }
            },
            else => {},
        }
    }

    var spectest_imports = imports.items[0];
    for (spectest_imports.tables.items) |*item| {
        std.testing.allocator.free(item.name);
        item.data.Host.deinit();
        std.testing.allocator.destroy(item.data.Host);
    }
    for (spectest_imports.memories.items) |*item| {
        std.testing.allocator.free(item.name);
        item.data.Host.deinit();
        std.testing.allocator.destroy(item.data.Host);
    }
    for (spectest_imports.globals.items) |*item| {
        std.testing.allocator.free(item.name);
        std.testing.allocator.destroy(item.data.Host);
    }

    for (imports.items[1..]) |*item| {
        item.deinit();
    }
    imports.deinit();

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
        "data",
        "elem",
        "endianness",
        "exports",
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
        "global",
        "i32",
        "i64",
        "if",
        "imports",
        "inline-module",
        "int_exprs",
        "int_literals",
        // "labels",
        // "left-to-right",
        // "linking",
        "load",
        "local_get",
        "local_set",
        "local_tee",
        "loop",
        "memory",
        "memory_copy",
        "memory_fill",
        "memory_grow",
        "memory_init",
        "memory_redundancy",
        "memory_size",
        "memory_trap",
        "names",
        "nop",
        "ref_func",
        "ref_is_null",
        "ref_null",
        "return",
        "select",
        // "skip-stack-guard-page",
        // "stack",
        "start",
        "store",
        "switch",
        "table",
        "table-sub",
        "table_copy",
        "table_fill",
        "table_get",
        "table_grow",
        "table_init",
        "table_set",
        "table_size",
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
