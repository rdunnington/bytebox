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
    UnknownExport,
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

const CFuncHandle = extern struct {
    index: u32,
    type: u32,
};

const CFuncInfo = extern struct {
    params: ?[*]const ValType,
    num_params: usize,
    returns: ?[*]const ValType,
    num_returns: usize,
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

const INVALID_FUNC_HANDLE = std.math.maxInt(u32);

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
        .UnknownExport => "BB_ERROR_UNKNOWNEXPORT",
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

export fn bb_module_instance_find_func(c_instance: CModuleInstance, c_func_name: ?[*:0]const c_char, out_handle: ?*CFuncHandle) CError {
    if (c_instance.module != null and c_func_name != null and out_handle != null) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));

        const func_name = std.mem.sliceTo(c_func_name.?, 0);

        out_handle.?.index = INVALID_FUNC_HANDLE;

        if (module.getFunctionHandle(func_name)) |handle| {
            out_handle.?.index = handle.index;
            out_handle.?.type = @enumToInt(handle.type);
            return CError.Ok;
        } else |err| {
            std.debug.assert(err == error.ExportUnknownFunction);
            return CError.UnknownExport;
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_func_info(c_instance: CModuleInstance, c_func_handle: CFuncHandle) CFuncInfo {
    if (c_instance.module != null and c_func_handle.index != INVALID_FUNC_HANDLE) {
        if (std.meta.intToEnum(core.FunctionHandleType, c_func_handle.type)) |handle_type| {
            var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));
            const func_handle = core.FunctionHandle{
                .index = c_func_handle.index,
                .type = handle_type,
            };

            const maybe_info: ?core.FunctionExport = module.getFunctionInfo(func_handle);
            if (maybe_info) |info| {
                return CFuncInfo{
                    .params = if (info.params.len > 0) info.params.ptr else null,
                    .num_params = info.params.len,
                    .returns = if (info.returns.len > 0) info.returns.ptr else null,
                    .num_returns = info.returns.len,
                };
            }
        } else |_| {} // intToEnum failed, user must have passed invalid data
    }

    return CFuncInfo{
        .params = null,
        .num_params = 0,
        .returns = null,
        .num_returns = 0,
    };
}

export fn bb_module_instance_invoke(c_instance: *CModuleInstance, c_handle: CFuncHandle, params: ?[*]const Val, num_params: usize, returns: ?[*]Val, num_returns: usize, opts: CModuleInstanceInvokeOpts) CError {
    if (c_instance.module != null and c_handle.index != INVALID_FUNC_HANDLE) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));

        const handle = core.FunctionHandle{
            .index = c_handle.index,
            .type = @intToEnum(core.FunctionHandleType, c_handle.type),
        };

        const invoke_opts = core.ModuleInstance.InvokeOpts{
            .trap_on_start = opts.trap_on_start,
        };

        var params_slice: []const Val = if (params != null) params.?[0..num_params] else &[_]Val{};
        var returns_slice: []Val = if (returns != null) returns.?[0..num_returns] else &[_]Val{};

        if (module.invoke(handle, params_slice, returns_slice, invoke_opts)) {
            return CError.Ok;
        } else |err| {
            return translateError(err);
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
        return if (mem.len > 0) mem.ptr else null;
    }

    return null;
}

export fn bb_module_instance_mem_all(c_instance: *CModuleInstance) CSlice {
    if (c_instance.module != null) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), c_instance.module.?));
        var mem = module.memoryAll();
        return CSlice{
            .data = mem.ptr,
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
