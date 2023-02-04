const std = @import("std");
const bytebox = @import("bytebox");

const Val = bytebox.Val;
const ValType = bytebox.ValType;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator: std.mem.Allocator = gpa.allocator();

    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2 or std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help")) {
        const usage_string: []const u8 =
            \\Usage: {s} <FILE> [OPTION]...
            \\  
            \\  Valid options:
            \\
            \\    -h, --help
            \\      Print help information.
            \\
            \\    -v, --version
            \\      Print version information.
            \\    
            \\    <FUNCTION> [ARGS]...
            \\      Call an exported, named function with arguments. The arguments are automatically
            \\      translated from string inputs to the function's native types. If the conversion
            \\      is not possible, an error is printed and execution aborts.
            \\
        ;
        std.log.info(usage_string, .{args[0]});
        return;
    } else if (std.mem.eql(u8, args[1], "-v") or std.mem.eql(u8, args[1], "--version")) {
        std.log.info("bytebox v0.0.1", .{});
        return;
    } else if (args[1][0] == '-') {
        std.log.warn("Unrecognized option '{s}'. Run bytebox with no arguments or with --help to print usage information.", .{args[1]});
        return;
    }

    const wasm_filename: []const u8 = args[1];

    var cwd = std.fs.cwd();
    var wasm_data: []u8 = cwd.readFileAlloc(allocator, wasm_filename, 1024 * 1024 * 128) catch |e| {
        std.log.err("Failed to read file '{s}' into memory: {}", .{ wasm_filename, e });
        return;
    };
    defer allocator.free(wasm_data);

    var module_def = bytebox.ModuleDefinition.init(allocator);
    defer module_def.deinit();

    module_def.decode(wasm_data) catch |e| {
        std.log.err("Caught error {} decoding module - invalid wasm.", .{e});
        return;
    };

    var module_instance = bytebox.ModuleInstance.init(&module_def, allocator);
    defer module_instance.deinit();

    module_instance.instantiate(.{}) catch |e| {
        std.log.err("Caught error {} instantiating module - invalid wasm.", .{e});
        return;
    };

    if (args.len == 2) {
        return;
    }

    const wasm_funcname: []const u8 = args[2];

    const func_info: ?bytebox.FunctionExportInfo = module_def.getFuncExportInfo(wasm_funcname);
    if (func_info == null) {
        std.log.err("Failed to find function '{s}' - either it doesn't exist or is not a public export.", .{wasm_funcname});
        return;
    }

    const num_params: usize = args.len - 3;
    if (func_info.?.params.len != num_params) {
        var strbuf = std.ArrayList(u8).init(allocator);
        defer strbuf.deinit();
        try writeSignature(&strbuf, &func_info.?);
        std.log.err("Specified {} params but expected {}. The signature of {s} is:\n{s}", .{ num_params, func_info.?.params.len, wasm_funcname, strbuf.items });
        return;
    }

    const wasm_args: [][]const u8 = args[3..];
    std.debug.assert(wasm_args.len == num_params);

    var params = std.ArrayList(bytebox.Val).init(allocator);
    defer params.deinit();
    try params.resize(wasm_args.len);
    for (func_info.?.params) |valtype, i| {
        const arg: []const u8 = wasm_args[i];
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

    module_instance.invoke(wasm_funcname, params.items, returns.items) catch |e| {
        std.log.err("Caught error {} during function invoke. The wasm program may have a bug.", .{e});
        return;
    };

    {
        var strbuf = std.ArrayList(u8).init(allocator);
        defer strbuf.deinit();
        var writer = strbuf.writer();

        try std.fmt.format(writer, "{s} completed with {} returns", .{ wasm_funcname, returns.items.len });
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
        std.log.info("{s}", .{strbuf.items});
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
