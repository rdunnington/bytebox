const std = @import("std");
const bytebox = @import("bytebox");
const wasi = bytebox.wasi;

const Val = bytebox.Val;
const ValType = bytebox.ValType;

const CmdOpts = struct {
    print_help: bool = false,
    print_version: bool = false,
    print_dump: bool = false,

    filename: ?[]const u8 = null,
    invoke: ?InvokeArgs = null,
    invalid_arg: ?[]const u8 = null,
    missing_options: ?[]const u8 = null,

    wasm_argv: ?[][]const u8 = null,
    wasm_env: ?[][]const u8 = null,
    wasm_dirs: ?[][]const u8 = null,
};

const InvokeArgs = struct {
    funcname: []const u8,
    args: [][]const u8,
};

fn isArgvOption(arg: []const u8) bool {
    return arg.len > 0 and arg[0] == '-';
}

fn parseCmdOpts(args: [][]const u8, env_buffer: *std.ArrayList([]const u8), dir_buffer: *std.ArrayList([]const u8)) CmdOpts {
    var opts = CmdOpts{};

    if (args.len < 2) {
        opts.print_help = true;
    }

    var arg_index: usize = 1;
    while (arg_index < args.len) {
        var arg = args[arg_index];

        if (arg_index == 1 and !isArgvOption(arg)) {
            opts.filename = arg;
            opts.wasm_argv = args[1..2];
        } else if (arg_index == 2 and !isArgvOption(arg)) {
            var wasm_argv_begin: usize = arg_index - 1; // include wasm filename
            var wasm_argv_end: usize = arg_index;
            while (wasm_argv_end + 1 < args.len and !isArgvOption(args[wasm_argv_end + 1])) {
                wasm_argv_end += 1;
            }
            opts.wasm_argv = args[wasm_argv_begin .. wasm_argv_end + 1];
            arg_index = wasm_argv_end;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            opts.print_help = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            opts.print_version = true;
        } else if (std.mem.eql(u8, arg, "--dump")) {
            if (opts.filename != null) {
                opts.print_dump = true;
            } else {
                opts.missing_options = arg;
            }
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--invoke")) {
            arg_index += 1;
            if (arg_index < args.len) {
                opts.invoke = InvokeArgs{
                    .funcname = args[arg_index],
                    .args = args[arg_index + 1 ..],
                };
            } else {
                opts.missing_options = arg;
            }
            arg_index = args.len;
        } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
            arg_index += 1;
            env_buffer.appendAssumeCapacity(args[arg_index]);
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--dir")) {
            arg_index += 1;
            dir_buffer.appendAssumeCapacity(args[arg_index]);
        } else {
            opts.invalid_arg = arg;
            break;
        }

        arg_index += 1;
    }

    if (env_buffer.items.len > 0) {
        opts.wasm_env = env_buffer.items;
    }

    if (dir_buffer.items.len > 0) {
        opts.wasm_dirs = dir_buffer.items;
    }

    return opts;
}

const version_string = "bytebox v0.0.1";

fn printHelp(args: [][]const u8) !void {
    const usage_string: []const u8 =
        \\Usage: {s} <FILE> [WASM_ARGS]... [OPTION]...
        \\  
        \\  Options:
        \\
        \\    -h, --help
        \\      Print help information.
        \\
        \\    -v, --version
        \\      Print version information.
        \\
        \\    --dump
        \\      Prints the given module definition's imports and exports. Imports are qualified
        \\      with the import module name.
        \\    
        \\    -i, --invoke <FUNCTION> [ARGS]...
        \\      Call an exported, named function with arguments. The arguments are automatically
        \\      translated from string inputs to the function's native types. If the conversion
        \\      is not possible, an error is printed and execution aborts.
        \\
        \\    -e, --env <ENVAR>
        \\      Set an environment variable for the execution environment. Typically retrieved
        \\      via the WASI API environ_sizes_get() and environ_get(). Multiple instances of
        \\      this flag is needed to pass multiple variables.
        \\
        \\   -d, --dir <PATH>
        \\     Allow WASI programs to access this directory and paths within it. Can be relative
        \\     to the current working directory or absolute. Multiple instances of this flag can
        \\     be used to pass multiple dirs.
        \\
        \\
    ;

    const stdout = std.io.getStdOut().writer();
    try stdout.print(usage_string, .{args[0]});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator: std.mem.Allocator = gpa.allocator();

    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var env_buffer = std.ArrayList([]const u8).init(allocator);
    defer env_buffer.deinit();
    try env_buffer.ensureTotalCapacity(4096); // 4096 vars should be enough for most insane script file scenarios.

    var dir_buffer = std.ArrayList([]const u8).init(allocator);
    defer dir_buffer.deinit();
    try dir_buffer.ensureTotalCapacity(4096);

    const opts: CmdOpts = parseCmdOpts(args, &env_buffer, &dir_buffer);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    if (opts.print_help) {
        try printHelp(args);
        return;
    } else if (opts.print_version) {
        try stdout.print("{s}", .{version_string});
        return;
    } else if (opts.invalid_arg) |invalid_arg| {
        try stderr.print("Invalid argument '{s}'.\n", .{invalid_arg});
        try printHelp(args);
        return;
    } else if (opts.missing_options) |missing_options| {
        try stderr.print("Argument {s} is missing required options.\n", .{missing_options});
        try printHelp(args);
        return;
    } else if (opts.invoke != null and opts.filename == null) {
        try stderr.print("Cannot invoke {s} without a file to load.", .{opts.invoke.?.funcname});
        try printHelp(args);
        return;
    }

    std.debug.assert(opts.filename != null);

    var cwd = std.fs.cwd();
    var wasm_data: []u8 = cwd.readFileAlloc(allocator, opts.filename.?, 1024 * 1024 * 128) catch |e| {
        std.log.err("Failed to read file '{s}' into memory: {}", .{ opts.filename.?, e });
        return;
    };
    defer allocator.free(wasm_data);

    var module_def = bytebox.ModuleDefinition.init(allocator);
    defer module_def.deinit();

    module_def.decode(wasm_data) catch |e| {
        std.log.err("Caught {} decoding module - invalid wasm.", .{e});
        return;
    };

    if (opts.print_dump) {
        var strbuf = std.ArrayList(u8).init(allocator);
        try strbuf.ensureTotalCapacity(1024 * 16);
        try module_def.dump(strbuf.writer());
        try stdout.print("{s}", .{strbuf.items});
        return;
    }

    var module_instance = bytebox.ModuleInstance.init(&module_def, allocator);
    defer module_instance.deinit();

    var imports_wasi: bytebox.ModuleImports = try wasi.initImports(.{
        .argv = opts.wasm_argv,
        .env = opts.wasm_env,
        .dirs = opts.wasm_dirs,
    }, allocator);
    defer wasi.deinitImports(&imports_wasi);

    var instantiate_opts = bytebox.ModuleInstantiateOpts{
        .imports = &[_]bytebox.ModuleImports{imports_wasi},
    };

    module_instance.instantiate(instantiate_opts) catch |e| {
        std.log.err("Caught {} instantiating module - invalid wasm.", .{e});
        return;
    };

    const invoke_funcname: []const u8 = if (opts.invoke) |invoke| invoke.funcname else "_start";
    const invoke_args: [][]const u8 = if (opts.invoke) |invoke| invoke.args else &[_][]u8{};

    const func_info: ?bytebox.FunctionExportInfo = module_def.getFuncExportInfo(invoke_funcname);
    if (func_info == null) {
        // don't log an error if the user didn't explicitly try to invoke a function
        if (opts.invoke != null) {
            std.log.err("Failed to find function '{s}' - either it doesn't exist or is not a public export.", .{invoke_funcname});
        }
        return;
    }

    const num_params: usize = invoke_args.len;
    if (func_info.?.params.len != num_params) {
        var strbuf = std.ArrayList(u8).init(allocator);
        defer strbuf.deinit();
        try writeSignature(&strbuf, &func_info.?);
        std.log.err("Specified {} params but expected {}. The signature of '{s}' is:\n{s}", .{
            num_params,
            func_info.?.params.len,
            invoke_funcname,
            strbuf.items,
        });
        return;
    }

    std.debug.assert(invoke_args.len == num_params);

    var params = std.ArrayList(bytebox.Val).init(allocator);
    defer params.deinit();
    try params.resize(invoke_args.len);
    for (func_info.?.params) |valtype, i| {
        const arg: []const u8 = invoke_args[i];
        switch (valtype) {
            .I32 => {
                var parsed: i32 = std.fmt.parseInt(i32, arg, 0) catch |e| {
                    std.log.err("Failed to parse arg at index {} ('{s}') as an i32: {}", .{ i, arg, e });
                    return;
                };
                params.items[i] = Val{ .I32 = parsed };
            },
            .I64 => {
                var parsed: i64 = std.fmt.parseInt(i64, arg, 0) catch |e| {
                    std.log.err("Failed to parse arg at index {} ('{s}') as an i64: {}", .{ i, arg, e });
                    return;
                };
                params.items[i] = Val{ .I64 = parsed };
            },
            .F32 => {
                var parsed: f32 = std.fmt.parseFloat(f32, arg) catch |e| {
                    std.log.err("Failed to parse arg at index {} ('{s}') as a f32: {}", .{ i, arg, e });
                    return;
                };
                params.items[i] = Val{ .F32 = parsed };
            },
            .F64 => {
                var parsed: f64 = std.fmt.parseFloat(f64, arg) catch |e| {
                    std.log.err("Failed to parse arg at index {} ('{s}') as a f64: {}", .{ i, arg, e });
                    return;
                };
                params.items[i] = Val{ .F64 = parsed };
            },
            .FuncRef => {
                std.log.err("Param at index {} is a funcref, making this function only invokeable from code.", .{i});
                return;
            },
            .ExternRef => {
                std.log.err("Param at index {} is an externref, making this function only invokeable from code.", .{i});
                return;
            },
        }
    }

    var returns = std.ArrayList(bytebox.Val).init(allocator);
    try returns.resize(func_info.?.returns.len);

    module_instance.invoke(invoke_funcname, params.items, returns.items) catch |e| {
        std.log.err("Caught {} during function invoke.", .{e});
        return;
    };

    {
        var strbuf = std.ArrayList(u8).init(allocator);
        defer strbuf.deinit();
        var writer = strbuf.writer();

        try std.fmt.format(writer, "'{s}' completed with {} returns", .{ invoke_funcname, returns.items.len });
        if (returns.items.len > 0) {
            try std.fmt.format(writer, ":\n", .{});
            for (returns.items) |val| {
                switch (val) {
                    .I32 => |v| try std.fmt.format(writer, "  {} (i32)\n", .{v}),
                    .I64 => |v| try std.fmt.format(writer, "  {} (i64)\n", .{v}),
                    .F32 => |v| try std.fmt.format(writer, "  {} (f32)\n", .{v}),
                    .F64 => |v| try std.fmt.format(writer, "  {} (f64)\n", .{v}),
                    .FuncRef => try std.fmt.format(writer, "  (funcref)\n", .{}),
                    .ExternRef => try std.fmt.format(writer, "  (externref)\n", .{}),
                }
            }
            try std.fmt.format(writer, "\n", .{});
        }
        try stdout.print("{s}\n", .{strbuf.items});
    }
}

fn writeSignature(strbuf: *std.ArrayList(u8), info: *const bytebox.FunctionExportInfo) !void {
    var writer = strbuf.writer();
    if (info.params.len == 0) {
        try std.fmt.format(writer, "  params: none\n", .{});
    } else {
        try std.fmt.format(writer, "  params:\n", .{});
        for (info.params) |valtype| {
            var name: []const u8 = valtypeToString(valtype);
            try std.fmt.format(writer, "    {s}\n", .{name});
        }
    }

    if (info.returns.len == 0) {
        try std.fmt.format(writer, "  returns: none\n", .{});
    } else {
        try std.fmt.format(writer, "  returns:\n", .{});
        for (info.returns) |valtype| {
            var name: []const u8 = valtypeToString(valtype);
            try std.fmt.format(writer, "    {s}\n", .{name});
        }
    }
}

fn valtypeToString(valtype: ValType) []const u8 {
    return switch (valtype) {
        inline else => |v| @typeInfo(ValType).Enum.fields[@enumToInt(v)].name,
    };
}
