const std = @import("std");
const core = @import("core.zig");
const StableArray = @import("zig-stable-array/stable_array.zig").StableArray;

// C interface
const ValType = core.ValType;
const Val = core.Val;
const ModuleImportPackage = core.ModuleImportPackage;
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

// TODO verify that although the C header defines module as CModuleInstance, it should just be the same as a raw pointer since it's a thin wrapper around a pointer
const CHostFunction = *const fn (userdata: ?*anyopaque, module: *core.ModuleInstance, params: [*]const Val, returns: [*]Val) void;

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
    package: ?*anyopaque,
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
// const FFIBinding = struct {
//     host: CHostFunction,
//     userdata: ?*anyopaque,
// };

// const FFIData = struct {
//     function_bindings: StableArray(FFIBinding),

//     fn alloc(allocator: std.mem.Allocator) !*FFIData {
//         var data: *FFIData = try allocator.create(FFIData);
//         const max_function_count = 1024 * 512;
//         data.function_bindings = StableArray(FFIBinding).init(max_function_count * @sizeOf(FFIBinding));
//         return data;
//     }

//     fn free(userdata: ?*anyopaque, allocator: std.mem.Allocator) void {
//         var data: *FFIData = fromUserdata(userdata);
//         data.function_bindings.deinit();
//         allocator.destroy(data);
//     }

//     fn fromUserdata(userdata: ?*anyopaque) *FFIData {
//         return @ptrCast(*FFIData, @alignCast(@alignOf(FFIData), userdata.?));
//     }
// };

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

export fn bb_module_definition_init(c_opts: CModuleDefinitionInitOpts) CModuleDefinition {
    var allocator = cffi_gpa.allocator();
    var module: ?*core.ModuleDefinition = allocator.create(core.ModuleDefinition) catch null;

    if (module) |m| {
        const debug_name: []const u8 = if (c_opts.debug_name == null) "" else std.mem.sliceTo(c_opts.debug_name.?, 0);
        const opts_translated = core.ModuleDefinitionOpts{
            .debug_name = debug_name,
        };
        m.* = core.ModuleDefinition.init(allocator, opts_translated);
    }

    return CModuleDefinition{
        .module = module,
    };
}

export fn bb_module_definition_deinit(c_definition: *CModuleDefinition) void {
    if (c_definition.module == null) {
        return;
    }
    var module = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), c_definition.module.?));
    module.deinit();

    var allocator = cffi_gpa.allocator();
    allocator.destroy(module);
}

export fn bb_module_definition_decode(c_definition: *CModuleDefinition, data: ?[*]c_char, length: usize) CError {
    if (c_definition.module != null and data != null) {
        var module = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), c_definition.module.?));
        const data_slice = data.?[0..length];
        if (module.decode(data_slice)) {
            return .Ok;
        } else |_| {
            return CError.Failed;
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_definition_get_custom_section(c_definition: *const CModuleDefinition, name: ?[*:0]const c_char) CSlice {
    if (c_definition.module != null and name != null) {
        var module = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), c_definition.module.?));
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

export fn bb_import_package_init(c_name: ?[*:0]const c_char) CImportPackage {
    var package: ?*ModuleImportPackage = null;
    var allocator = cffi_gpa.allocator();

    if (c_name != null) {
        package = allocator.create(ModuleImportPackage) catch null;

        if (package) |p| {
            const name: []const u8 = std.mem.sliceTo(c_name.?, 0);
            p.* = ModuleImportPackage.init(name, null, null, allocator) catch {
                allocator.destroy(p);
                return CImportPackage{ .package = null };
            };
        }
    }

    return CImportPackage{
        .package = package,
    };
}

export fn bb_import_package_deinit(c_package: ?*CImportPackage) void {
    if (c_package != null and c_package.?.package != null) {
        var package = @ptrCast(*ModuleImportPackage, @alignCast(@alignOf(ModuleImportPackage), c_package.?.package.?));
        package.deinit();
    }
}

export fn bb_import_package_userdata(c_package: ?*CImportPackage) ?*anyopaque {
    if (c_package != null and c_package.?.package != null) {
        var package = @ptrCast(*ModuleImportPackage, @alignCast(@alignOf(ModuleImportPackage), c_package.?.package.?));
        return package.userdata;
    }

    return null;
}

export fn bb_import_package_add_function(c_package: ?*CImportPackage, func: ?CHostFunction, c_name: ?[*:0]const c_char, c_params: ?[*]ValType, num_params: usize, c_returns: ?[*]ValType, num_returns: usize, userdata: ?*anyopaque) CError {
    if (c_package != null and c_package.?.package != null and c_name != null and func != null) {
        if (num_params > 0 and c_params == null) {
            return CError.InvalidParameter;
        }
        if (num_returns > 0 and c_returns == null) {
            return CError.InvalidParameter;
        }

        // var ffi_data = FFIData.fromUserdata(package.userdata);

        // ffi_data.function_bindings.append(FFIBinding{
        //     .host = func,
        //     .userdata = userdata,
        // }) catch return CError.OutOfMemory;

        const name: []const u8 = std.mem.sliceTo(c_name.?, 0);
        const param_types: []ValType = if (c_params) |params| params[0..num_params] else &[_]ValType{};
        const return_types: []ValType = if (c_returns) |returns| returns[0..num_returns] else &[_]ValType{};

        var package = @ptrCast(*ModuleImportPackage, @alignCast(@alignOf(ModuleImportPackage), c_package.?.package.?));

        package.addHostFunction(name, param_types, return_types, func.?, userdata) catch {
            return CError.OutOfMemory;
        };
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_init(c_definition: *CModuleDefinition) CModuleInstance {
    var allocator = cffi_gpa.allocator();

    var module: ?*core.ModuleInstance = null;

    if (c_definition.module != null) {
        var module_definition = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), c_definition.module.?));
        module = allocator.create(core.ModuleInstance) catch null;

        if (module) |m| {
            m.* = core.ModuleInstance.init(module_definition, allocator);
        }
    }

    return CModuleInstance{
        .module = module,
    };
}

export fn bb_module_instance_deinit(c_instance: *CModuleInstance) void {
    if (c_instance.module == null) {
        return;
    }

    var allocator = cffi_gpa.allocator();

    var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));
    module.deinit();

    allocator.destroy(module);
}

export fn bb_module_instance_instantiate(c_instance: *CModuleInstance, c_opts: CModuleInstanceInstantiateOpts) CError {
    if (c_instance.module != null and c_opts.packages != null) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));

        var allocator = cffi_gpa.allocator();

        var packages = std.ArrayList(ModuleImportPackage).init(allocator);
        packages.ensureTotalCapacityPrecise(c_opts.num_packages) catch return CError.OutOfMemory;
        defer {
            for (packages.items) |*package| {
                package.deinit();
            }
            packages.deinit();
        }

        if (c_opts.packages != null) {
            const c_packages: []const CImportPackage = c_opts.packages.?[0..c_opts.num_packages];
            for (c_packages) |c_package| {
                var package = @ptrCast(*ModuleImportPackage, @alignCast(@alignOf(ModuleImportPackage), c_package.package.?));
                packages.appendAssumeCapacity(package.*);
            }
        }

        // var ffi_data = FFIData.fromUserdata(module.userdata);

        // preallocate binding data to ensure memory doesn't move so we can pass out pointers into it
        // {
        //     var num_function_bindings: usize = 0;
        //     for (c_packages) |c_package| {
        //         num_function_bindings += c_package.num_functions;
        //     }
        //     ffi_data.function_bindings.ensureTotalCapacity(num_function_bindings) catch |err| return translateError(err);
        // }

        // packages.ensureTotalCapacityPrecise(c_packages.len) catch |err| return translateError(err);
        // for (c_packages) |c_package| {
        //     if (c_package.functions) |c_functions| {
        //         const package_name: []const u8 = if (c_package.name != null) std.mem.sliceTo(c_package.name.?, 0) else "";

        //         var package = ModuleImportPackage.init(package_name, null, null, allocator) catch |err| return translateError(err);

        //         const c_functions_slice = c_functions[0..c_package.num_functions];
        //         for (c_functions_slice) |c_function| {
        //             if (c_function.func != null) {
        //                 const ffi_binding = FFIBinding{
        //                     .host = c_function.func.?,
        //                     .userdata = c_function.userdata,
        //                 };
        //                 // ffi_data.function_bindings.appendAssumeCapacity(ffi_binding);

        //                 const function_name: []const u8 = if (c_function.name != null) std.mem.sliceTo(c_function.name.?, 0) else return CError.InvalidParameter;

        //                 if (c_function.params == null and c_function.num_params > 0) return CError.InvalidParameter;
        //                 if (c_function.returns == null and c_function.num_returns > 0) return CError.InvalidParameter;

        //                 const param_types: []ValType = if (c_function.params) |params| params[0..c_function.num_params] else &[_]ValType{};
        //                 const return_types: []ValType = if (c_function.returns) |returns| returns[0..c_function.num_returns] else &[_]ValType{};

        //                 package.addHostFunction(
        //                     function_name,
        //                     param_types,
        //                     return_types,
        //                     hostFunctionShim,
        //                     &ffi_data.function_bindings.items[ffi_data.function_bindings.items.len - 1],
        //                 ) catch |err| return translateError(err);
        //             }
        //         }

        //         packages.append(package) catch |err| return translateError(err);
        //     }
        // }

        const opts = core.ModuleInstantiateOpts{
            .imports = packages.items,
            .enable_debug = c_opts.enable_debug,
        };

        if (module.instantiate(opts)) {
            return CError.Ok;
        } else |err| {
            return translateError(err);
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_invoke(c_instance: *CModuleInstance, func_name: ?[*:0]const c_char, params: ?[*]const Val, num_params: usize, returns: ?[*]Val, num_returns: usize, opts: CModuleInstanceInvokeOpts) CError {
    if (c_instance.module != null and func_name != null) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));

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

export fn bb_module_instance_resume(c_instance: *CModuleInstance, returns: ?[*]Val, num_returns: usize) CError {
    _ = c_instance;
    _ = returns;
    _ = num_returns;
    return CError.Failed;
}

export fn bb_module_instance_step(c_instance: *CModuleInstance, returns: ?[*]Val, num_returns: usize) CError {
    _ = c_instance;
    _ = returns;
    _ = num_returns;
    return CError.Failed;
}

export fn bb_module_instance_debug_set_trap(c_instance: *CModuleInstance, address: u32, trap_mode: CDebugTrapMode) CError {
    _ = c_instance;
    _ = address;
    _ = trap_mode;
    return CError.Failed;
}

export fn bb_module_instance_mem(c_instance: *CModuleInstance, offset: usize, length: usize) ?*anyopaque {
    if (c_instance.module != null and length > 0) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));

        var mem = module.memorySlice(offset, length);
        // var ptr: ?[*]c_char = if (mem.len > 0) @ptrCast([*]c_char, mem.ptr) else null;
        // return ptr;
        return if (mem.len > 0) mem.ptr else null;
    }

    return null;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local helpers

fn translateError(err: anyerror) CError {
    switch (err) {
        error.OutOfMemory => return CError.OutOfMemory,
        else => return CError.Failed,
    }
}

// fn hostFunctionShim(userdata: ?*anyopaque, module: *core.ModuleInstance, params: []const Val, returns: []Val) void {
//     const binding = @ptrCast(*FFIBinding, @alignCast(@alignOf(FFIBinding), userdata.?));
//     var c_module = CModuleInstance{
//         .module = module,
//     };

//     binding.host(binding.userdata, &c_module, params.ptr, returns.ptr);
// }
