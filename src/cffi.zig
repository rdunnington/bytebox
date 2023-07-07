const std = @import("std");
const core = @import("core.zig");

// C interface
const ValType = core.ValType;
const Val = core.Val;
const c_char = u8;

const CSlice = extern struct {
    data: ?[*]c_char,
    length: usize,
};

const CError = enum(c_int) {
    Ok,
    Failed,
    OutOfMemory,
    InvalidParameter,
};

const CModuleDefinitionInitOpts = extern struct {
    debug_name: ?[*:0]c_char,
};

const CModuleDefinition = extern struct {
    module: ?*anyopaque,
};

const CHostFunction = *const fn (userdata: ?*anyopaque, module: *CModuleInstance, params: [*]const Val, returns: [*]Val) void;

const CImportFunction = extern struct {
    name: ?[*:0]c_char,
    func: ?CHostFunction,
    params: ?[*]ValType,
    num_params: usize,
    returns: ?[*]ValType,
    num_returns: usize,
    userdata: ?*anyopaque,
};

const CImportPackage = extern struct {
    name: ?[*:0]c_char,
    functions: ?[*]CImportFunction,
    num_functions: usize,
};

const CModuleInstanceInstantiateOpts = extern struct {
    packages: ?[*]CImportPackage,
    num_packages: usize,
    enable_debug: bool,
};

const CModuleInstance = extern struct {
    module: ?*anyopaque,
};

const CModuleInstanceInvokeOpts = extern struct {
    trap_on_start: bool,
};

const CDebugTrapMode = enum(c_int) {
    Disabled,
    Enabled,
};

// Local data
const FFIBinding = struct {
    host: CHostFunction,
    userdata: ?*anyopaque,
};

const FFIData = struct {
    function_bindings: std.ArrayList(FFIBinding),

    fn alloc(allocator: std.mem.Allocator) !*FFIData {
        var data: *FFIData = try allocator.create(FFIData);
        data.function_bindings = std.ArrayList(FFIBinding).init(allocator);
        return data;
    }

    fn free(allocator: std.mem.Allocator, userdata: ?*anyopaque) void {
        var data: *FFIData = fromUserdata(userdata);
        data.function_bindings.deinit();
        allocator.destroy(data);
    }

    fn fromUserdata(userdata: ?*anyopaque) *FFIData {
        return @ptrCast(*FFIData, @alignCast(@alignOf(FFIData), userdata.?));
    }
};

// TODO logging callback as well?
// TODO allocator hooks
// const CAllocFunc = *const fn (size: usize, userdata: ?*anyopaque) ?*anyopaque;
// const CReallocFunc = *const fn (mem: ?*anyopaque, size: usize, userdata: ?*anyopaque) ?*anyopaque;
// const CFreeFunc = *const fn (mem: ?*anyopaque, userdata: ?*anyopaque) void;

var cffi_gpa = std.heap.GeneralPurposeAllocator(.{}){};

// const CAllocator = struct {
// 	const AllocError = std.mem.Allocator.Error;

//     fallback: FallbackAllocator,
//     alloc_func: ?CAllocFunc = null,
//     realloc_func: ?CReallocFunc = null,
//     free_func: ?CFreeFunc = null,
//     userdata: ?*anyopaque = null,

//     fn allocator(self: *CAllocator) std.mem.Allocator() {
//         if (alloc_func != null and realloc_func != null and free_func != null) {
//             return std.mem.Allocator.init(
//             	self,
//                 alloc,
//                 resize,
//                 free
//             );
//         } else {
//             return fallback.allocator();
//         }
//     }

//     fn alloc(ptr: *anyopaque, len: usize, ptr_align: u29, len_align: u29, ret_addr: usize) AllocError![]u8 {
//     	_ = ret_addr;

//     	var allocator = @ptrCast(*CAllocator, @alignCast(@alignOf(CAllocator), ptr));
//     	const size =
//     	const mem_or_null: ?[*]anyopaque = allocator.alloc_func(size, allocator.userdata);
//     	if (mem_or_null) |mem| {
//     		var bytes = @ptrCast([*]u8, @alignCast(1, mem));
//     		return bytes[0..size];
//     	} else {
//     		return AllocError.OutOfMemory;
//     	}
//     }

//     fn resize(ptr: *anyopaque, buf: []u8, buf_align: u29, new_len: usize, len_align: u29, ret_addr: usize) ?usize {

// 	}

// 	fn free(ptr: *anyopaque, buf: []u8, buf_align: u29, ret_addr: usize) void {

// 	}
// };

// var cffi_allocator = CAllocator{ .fallback = FallbackAllocator{} };

// export fn bb_set_memory_hooks(alloc_func: CAllocFunc, realloc_func: CReallocFunc, free_func: CFreeFunc, userdata: ?*anyopaque) void {
//     cffi_allocator.alloc_func = alloc_func;
//     cffi_allocator.realloc_func = realloc_func;
//     cffi_allocator.free_func = free_func;
//     cffi_allocator.userdata = userdata;
// }

export fn bb_error_str(c_error: CError) [*]const c_char {
    return switch (c_error) {
        .Ok => "BB_ERROR_OK",
        .Failed => "BB_ERROR_FAILED",
        .OutOfMemory => "BB_ERROR_OUTOFMEMORY",
        .InvalidParameter => "BB_ERROR_INVALIDPARAMETER",
    };
}

export fn bb_module_definition_init(opts: CModuleDefinitionInitOpts) CModuleDefinition {
    var allocator = cffi_gpa.allocator();
    var module: ?*core.ModuleDefinition = allocator.create(core.ModuleDefinition) catch null;

    if (module) |m| {
        const debug_name: []const u8 = if (opts.debug_name == null) "" else std.mem.sliceTo(opts.debug_name.?, 0);
        const opts_translated = core.ModuleDefinitionOpts{
            .debug_name = debug_name,
        };
        m.* = core.ModuleDefinition.init(allocator, opts_translated);
    }

    return CModuleDefinition{
        .module = module,
    };
}

export fn bb_module_definition_deinit(definition: *CModuleDefinition) void {
    if (definition.module == null) {
        return;
    }
    var module = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), definition.module.?));
    module.deinit();

    var allocator = cffi_gpa.allocator();
    allocator.destroy(module);
}

export fn bb_module_definition_decode(definition: *CModuleDefinition, data: ?[*]c_char, length: usize) CError {
    if (definition.module != null and data != null) {
        var module = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), definition.module.?));
        const data_slice = data.?[0..length];
        if (module.decode(data_slice)) {
            return .Ok;
        } else |_| {
            return CError.Failed;
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_definition_get_custom_section(definition: *const CModuleDefinition, name: ?[*:0]const c_char) CSlice {
    if (definition.module != null and name != null) {
        var module = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), definition.module.?));
        const name_slice: []const u8 = std.mem.sliceTo(name.?, 0);
        if (module.getCustomSection(name_slice)) |section_data| {
            return CSlice{
                .data = section_data.ptr,
                .length = section_data.len,
            };
        }
    }

    return CSlice{
        .data = null,
        .length = 0,
    };
}

export fn bb_module_instance_init(definition: *CModuleDefinition) CModuleInstance {
    var allocator = cffi_gpa.allocator();

    var module: ?*core.ModuleInstance = null;
    var ffi_data: ?*FFIData = FFIData.alloc(allocator) catch null;

    if (definition.module != null and ffi_data != null) {
        var module_definition = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), definition.module.?));
        module = allocator.create(core.ModuleInstance) catch null;

        if (module) |m| {
            m.* = core.ModuleInstance.init(module_definition, allocator);
            m.userdata = ffi_data;
        }
    }

    return CModuleInstance{
        .module = module,
    };
}

export fn bb_module_instance_deinit(instance: *CModuleInstance) void {
    if (instance.module == null) {
        return;
    }

    var allocator = cffi_gpa.allocator();

    var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), instance.module.?));
    FFIData.free(allocator, module.userdata);

    module.deinit();

    allocator.destroy(module);
}

export fn bb_module_instance_instantiate(instance: *CModuleInstance, opts: CModuleInstanceInstantiateOpts) CError {
    if (instance.module != null and opts.packages != null) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), instance.module.?));

        var allocator = cffi_gpa.allocator();

        var packages = std.ArrayList(core.ModuleImportPackage).init(allocator);
        defer {
            for (packages.items) |*package| {
                package.deinit();
            }
            packages.deinit();
        }

        const c_packages: []const CImportPackage = opts.packages.?[0..opts.num_packages];

        var ffi_data = FFIData.fromUserdata(module.userdata);

        // preallocate binding data to ensure memory doesn't move so we can pass out pointers into it
        {
            var num_function_bindings: usize = 0;
            for (c_packages) |c_package| {
                num_function_bindings += c_package.num_functions;
            }
            ffi_data.function_bindings.ensureTotalCapacity(num_function_bindings) catch |err| return translateError(err);
        }

        packages.ensureTotalCapacityPrecise(c_packages.len) catch |err| return translateError(err);
        for (c_packages) |c_package| {
            if (c_package.functions) |c_functions| {
                const package_name: []const u8 = if (c_package.name != null) std.mem.sliceTo(c_package.name.?, 0) else "";

                var package = core.ModuleImportPackage.init(package_name, null, null, allocator) catch |err| return translateError(err);

                const c_functions_slice = c_functions[0..c_package.num_functions];
                for (c_functions_slice) |c_function| {
                    if (c_function.func != null) {
                        const ffi_binding = FFIBinding{
                            .host = c_function.func.?,
                            .userdata = c_function.userdata,
                        };
                        ffi_data.function_bindings.appendAssumeCapacity(ffi_binding);

                        const function_name: []const u8 = if (c_function.name != null) std.mem.sliceTo(c_function.name.?, 0) else return CError.InvalidParameter;

                        if (c_function.params == null and c_function.num_params > 0) return CError.InvalidParameter;
                        if (c_function.returns == null and c_function.num_returns > 0) return CError.InvalidParameter;

                        const param_types: []ValType = if (c_function.params) |params| params[0..c_function.num_params] else &[_]ValType{};
                        const return_types: []ValType = if (c_function.returns) |returns| returns[0..c_function.num_returns] else &[_]ValType{};

                        package.addHostFunction(
                            function_name,
                            param_types,
                            return_types,
                            hostFunctionShim,
                            &ffi_data.function_bindings.items[ffi_data.function_bindings.items.len - 1],
                        ) catch |err| return translateError(err);
                    }
                }

                packages.append(package) catch |err| return translateError(err);
            }
        }

        const opts_translated = core.ModuleInstantiateOpts{
            .imports = packages.items,
            .enable_debug = opts.enable_debug,
        };

        if (module.instantiate(opts_translated)) {
            return CError.Ok;
        } else |err| {
            return translateError(err);
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_invoke(instance: *CModuleInstance, func_name: ?[*:0]const c_char, params: ?[*]const Val, num_params: usize, returns: ?[*]Val, num_returns: usize, opts: CModuleInstanceInvokeOpts) CError {
    if (instance.module != null and func_name != null) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), instance.module.?));

        const func_name_slice = std.mem.sliceTo(func_name.?, 0);

        if (module.module_def.getFunctionExport(func_name_slice)) |func_export| {
            if (func_export.params.len != num_params or func_export.params.len > 0 and params == null) {
                return CError.InvalidParameter;
            }
            if (func_export.returns.len != num_returns or func_export.returns.len > 0 and returns == null) {
                return CError.InvalidParameter;
            }

            const invoke_opts = core.ModuleInstance.InvokeOpts{
                .trap_on_start = opts.trap_on_start,
            };

            var params_slice: []const Val = if (params != null) params.?[0..num_params] else &[_]Val{};
            var returns_slice: []Val = if (returns != null) returns.?[0..num_returns] else &[_]Val{};

            if (module.invoke(func_name_slice, params_slice, returns_slice, invoke_opts)) {
                return CError.Ok;
            } else |err| {
                return translateError(err);
            }
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_resume(instance: *CModuleInstance, returns: ?[*]Val, num_returns: usize) CError {
    _ = instance;
    _ = returns;
    _ = num_returns;
    return CError.Failed;
}

export fn bb_module_instance_step(instance: *CModuleInstance, returns: ?[*]Val, num_returns: usize) CError {
    _ = instance;
    _ = returns;
    _ = num_returns;
    return CError.Failed;
}

export fn bb_module_instance_debug_set_trap(instance: *CModuleInstance, address: u32, trap_mode: CDebugTrapMode) CError {
    _ = instance;
    _ = address;
    _ = trap_mode;
    return CError.Failed;
}

export fn bb_module_instance_mem(instance: *CModuleInstance, offset: usize, length: usize) CSlice {
    if (instance.module != null and length > 0) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), instance.module.?));

        var mem = module.memorySlice(offset, length);
        var ptr: ?[*]c_char = if (mem.len > 0) @ptrCast([*]c_char, mem.ptr) else null;
        return CSlice{
            .data = ptr,
            .length = mem.len,
        };
    }

    return CSlice{
        .data = null,
        .length = 0,
    };
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local helpers

fn translateError(err: anyerror) CError {
    switch (err) {
        error.OutOfMemory => return CError.OutOfMemory,
        else => return CError.Failed,
    }
}

fn hostFunctionShim(userdata: ?*anyopaque, module: *core.ModuleInstance, params: []const Val, returns: []Val) void {
    const binding = @ptrCast(*FFIBinding, @alignCast(@alignOf(FFIBinding), userdata.?));
    var c_module = CModuleInstance{
        .module = module,
    };

    binding.host(binding.userdata, &c_module, params.ptr, returns.ptr);
}
