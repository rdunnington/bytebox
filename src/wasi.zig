const core = @import("core.zig");

const ModuleInstance = core.ModuleInstance;

//  args_get(argv: Pointer<Pointer<u8>>, argv_buf: Pointer<u8>) -> Result<(), errno>
fn wasi_args_sizes_get(module: *ModuleInstance, _: ?*anyopaque, params: []const Val, returns: []Val) void {
    // std.debug.assert(params.len == 1);
    // std.debug.assert(returns.len == 0);
    // std.debug.assert(std.meta.activeTag(params[0]) == ValType.I32);
    // std.debug.print("{}", .{params[0].I32});
}

pub fn makeWasiImports(allocator: std.mem.Allocator) !bytebox.ModuleImports {
    var imports: bytebox.ModuleImports = try bytebox.ModuleImports.init("spectest", null, allocator);

    const void_returns = &[0]ValType{};

    try imports.addHostFunction("args_sizes_get", null, &[_]ValType{.I32}, &[_]ValType{ .I32, .I32 }, wasi_args_sizes_get);
    // try imports.addHostFunction("print_i64", null, &[_]ValType{.I64}, void_returns, Functions.printI64);
    // try imports.addHostFunction("print_f32", null, &[_]ValType{.F32}, void_returns, Functions.printF32);
    // try imports.addHostFunction("print_f64", null, &[_]ValType{.F64}, void_returns, Functions.printF64);
    // try imports.addHostFunction("print_i32_f32", null, &[_]ValType{ .I32, .F32 }, void_returns, Functions.printI32F32);
    // try imports.addHostFunction("print_f64_f64", null, &[_]ValType{ .F64, .F64 }, void_returns, Functions.printF64F64);
    // try imports.addHostFunction("print_f64_f64", null, &[_]ValType{ .F64, .F64 }, void_returns, Functions.printF64F64);
    // try imports.addHostFunction("print", null, &[_]ValType{}, void_returns, Functions.print);

    return imports;
}
