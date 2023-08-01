const std = @import("std");
const core = @import("core.zig");
const StableArray = @import("zig-stable-array/stable_array.zig").StableArray;

const ValType = core.ValType;
const Val = core.Val;
const ModuleDefinition = core.ModuleDefinition;
const ModuleInstance = core.ModuleInstance;
const ModuleImportPackage = core.ModuleImportPackage;
const c_char = u8;

// C interface
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
    UnknownImport,
    IncompatibleImport,
};

const CModuleDefinitionInitOpts = extern struct {
    debug_name: ?[*:0]c_char,
};

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

const CModuleInstanceInstantiateOpts = extern struct {
    packages: ?[*]?*const ModuleImportPackage,
    num_packages: usize,
    enable_debug: bool,
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

// TODO logging callback as well?
// TODO allocator hooks
// const CAllocFunc = *const fn (size: usize, userdata: ?*anyopaque) ?*anyopaque;
// const CReallocFunc = *const fn (mem: ?*anyopaque, size: usize, userdata: ?*anyopaque) ?*anyopaque;
// const CFreeFunc = *const fn (mem: ?*anyopaque, userdata: ?*anyopaque) void;

const INVALID_FUNC_INDEX = std.math.maxInt(u32);

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

export fn bb_error_str(c_error: CError) [*:0]const c_char {
    return switch (c_error) {
        .Ok => "BB_ERROR_OK",
        .Failed => "BB_ERROR_FAILED",
        .OutOfMemory => "BB_ERROR_OUTOFMEMORY",
        .InvalidParameter => "BB_ERROR_INVALIDPARAMETER",
        .UnknownExport => "BB_ERROR_UNKNOWNEXPORT",
        .UnknownImport => "BB_ERROR_UNKNOWNIMPORT",
        .IncompatibleImport => "BB_ERROR_INCOMPATIBLEIMPORT",
    };
}

export fn bb_module_definition_init(c_opts: CModuleDefinitionInitOpts) ?*core.ModuleDefinition {
    var allocator = cffi_gpa.allocator();
    var module: ?*core.ModuleDefinition = allocator.create(core.ModuleDefinition) catch null;

    if (module) |m| {
        const debug_name: []const u8 = if (c_opts.debug_name == null) "" else std.mem.sliceTo(c_opts.debug_name.?, 0);
        const opts_translated = core.ModuleDefinitionOpts{
            .debug_name = debug_name,
        };
        m.* = core.ModuleDefinition.init(allocator, opts_translated);
    }

    return module;
}

export fn bb_module_definition_deinit(module: ?*core.ModuleDefinition) void {
    if (module) |m| {
        m.deinit();

        var allocator = cffi_gpa.allocator();
        allocator.destroy(m);
    }
}

export fn bb_module_definition_decode(module: ?*core.ModuleDefinition, data: ?[*]c_char, length: usize) CError {
    if (module != null and data != null) {
        const data_slice = data.?[0..length];
        if (module.?.decode(data_slice)) {
            return .Ok;
        } else |_| {
            return CError.Failed;
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_definition_get_custom_section(module: ?*core.ModuleDefinition, name: ?[*:0]const c_char) CSlice {
    if (module != null and name != null) {
        const name_slice: []const u8 = std.mem.sliceTo(name.?, 0);
        if (module.?.getCustomSection(name_slice)) |section_data| {
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

export fn bb_import_package_init(c_name: ?[*:0]const c_char) ?*ModuleImportPackage {
    var package: ?*ModuleImportPackage = null;
    var allocator = cffi_gpa.allocator();

    if (c_name != null) {
        package = allocator.create(ModuleImportPackage) catch null;

        if (package) |p| {
            const name: []const u8 = std.mem.sliceTo(c_name.?, 0);
            p.* = ModuleImportPackage.init(name, null, null, allocator) catch {
                allocator.destroy(p);
                return null;
            };
        }
    }

    return package;
}

export fn bb_import_package_deinit(package: ?*ModuleImportPackage) void {
    if (package) |p| {
        p.deinit();
    }
}

export fn bb_import_package_add_function(package: ?*ModuleImportPackage, func: ?CHostFunction, c_name: ?[*:0]const c_char, c_params: ?[*]ValType, num_params: usize, c_returns: ?[*]ValType, num_returns: usize, userdata: ?*anyopaque) CError {
    if (package != null and c_name != null and func != null) {
        if (num_params > 0 and c_params == null) {
            return CError.InvalidParameter;
        }
        if (num_returns > 0 and c_returns == null) {
            return CError.InvalidParameter;
        }

        const name: []const u8 = std.mem.sliceTo(c_name.?, 0);
        const param_types: []ValType = if (c_params) |params| params[0..num_params] else &[_]ValType{};
        const return_types: []ValType = if (c_returns) |returns| returns[0..num_returns] else &[_]ValType{};

        package.?.addHostFunction(name, param_types, return_types, func.?, userdata) catch {
            return CError.OutOfMemory;
        };
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_init(module_definition: ?*ModuleDefinition) ?*ModuleInstance {
    var allocator = cffi_gpa.allocator();

    var module: ?*core.ModuleInstance = null;

    if (module_definition != null) {
        module = allocator.create(core.ModuleInstance) catch null;

        if (module) |m| {
            m.* = core.ModuleInstance.init(module_definition.?, allocator);
        }
    }

    return module;
}

export fn bb_module_instance_deinit(module: ?*ModuleInstance) void {
    var allocator = cffi_gpa.allocator();

    if (module) |m| {
        m.deinit();
        allocator.destroy(m);
    }
}

export fn bb_module_instance_instantiate(module: ?*ModuleInstance, c_opts: CModuleInstanceInstantiateOpts) CError {
    if (module != null and c_opts.packages != null) {
        const packages: []?*const ModuleImportPackage = c_opts.packages.?[0..c_opts.num_packages];

        var allocator = cffi_gpa.allocator();
        var flat_packages = std.ArrayList(ModuleImportPackage).init(allocator);
        defer flat_packages.deinit();

        flat_packages.ensureTotalCapacityPrecise(packages.len) catch return CError.OutOfMemory;
        for (packages) |p| {
            if (p != null) {
                flat_packages.appendAssumeCapacity(p.?.*);
            }
        }

        const opts = core.ModuleInstantiateOpts{
            .imports = flat_packages.items,
            .enable_debug = c_opts.enable_debug,
        };

        if (module.?.instantiate(opts)) {
            return CError.Ok;
        } else |err| {
            return translateError(err);
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_find_func(module: ?*ModuleInstance, c_func_name: ?[*:0]const c_char, out_handle: ?*CFuncHandle) CError {
    if (module != null and c_func_name != null and out_handle != null) {
        const func_name = std.mem.sliceTo(c_func_name.?, 0);

        out_handle.?.index = INVALID_FUNC_INDEX;

        if (module.?.getFunctionHandle(func_name)) |handle| {
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

export fn bb_module_instance_func_info(module: ?*ModuleInstance, c_func_handle: CFuncHandle) CFuncInfo {
    if (module != null and c_func_handle.index != INVALID_FUNC_INDEX) {
        if (std.meta.intToEnum(core.FunctionHandleType, c_func_handle.type)) |handle_type| {
            const func_handle = core.FunctionHandle{
                .index = c_func_handle.index,
                .type = handle_type,
            };

            const maybe_info: ?core.FunctionExport = module.?.getFunctionInfo(func_handle);
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

export fn bb_module_instance_invoke(module: ?*ModuleInstance, c_handle: CFuncHandle, params: ?[*]const Val, num_params: usize, returns: ?[*]Val, num_returns: usize, opts: CModuleInstanceInvokeOpts) CError {
    if (module != null and c_handle.index != INVALID_FUNC_INDEX) {
        const handle = core.FunctionHandle{
            .index = c_handle.index,
            .type = @intToEnum(core.FunctionHandleType, c_handle.type),
        };

        const invoke_opts = core.ModuleInstance.InvokeOpts{
            .trap_on_start = opts.trap_on_start,
        };

        var params_slice: []const Val = if (params != null) params.?[0..num_params] else &[_]Val{};
        var returns_slice: []Val = if (returns != null) returns.?[0..num_returns] else &[_]Val{};

        if (module.?.invoke(handle, params_slice, returns_slice, invoke_opts)) {
            return CError.Ok;
        } else |err| {
            return translateError(err);
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_resume(module: ?*ModuleInstance, returns: ?[*]Val, num_returns: usize) CError {
    _ = module;
    _ = returns;
    _ = num_returns;
    return CError.Failed;
}

export fn bb_module_instance_step(module: ?*ModuleInstance, returns: ?[*]Val, num_returns: usize) CError {
    _ = module;
    _ = returns;
    _ = num_returns;
    return CError.Failed;
}

export fn bb_module_instance_debug_set_trap(module: ?*ModuleInstance, address: u32, trap_mode: CDebugTrapMode) CError {
    _ = module;
    _ = address;
    _ = trap_mode;
    return CError.Failed;
}

export fn bb_module_instance_mem(module: ?*ModuleInstance, offset: usize, length: usize) ?*anyopaque {
    if (module != null and length > 0) {
        var mem = module.?.memorySlice(offset, length);
        return if (mem.len > 0) mem.ptr else null;
    }

    return null;
}

export fn bb_module_instance_mem_all(module: ?*ModuleInstance) CSlice {
    if (module != null) {
        var mem = module.?.memoryAll();
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

const CGlobalMut = enum(c_int) {
    Immutable = 0,
    Mutable = 1,
};

const CGlobalExport = extern struct {
    value: ?*Val,
    type: ValType,
    mut: CGlobalMut,
};

export fn bb_module_instance_find_global(module: ?*ModuleInstance, c_global_name: ?[*:0]const c_char) CGlobalExport {
    comptime {
        std.debug.assert(@enumToInt(CGlobalMut.Immutable) == @enumToInt(core.GlobalMut.Immutable));
        std.debug.assert(@enumToInt(CGlobalMut.Mutable) == @enumToInt(core.GlobalMut.Mutable));
    }

    if (module != null and c_global_name != null) {
        const global_name = std.mem.sliceTo(c_global_name.?, 0);
        if (module.?.getGlobalExport(global_name)) |global| {
            return CGlobalExport{
                .value = global.val,
                .type = global.valtype,
                .mut = @intToEnum(CGlobalMut, @enumToInt(global.mut)),
            };
        } else |_| {}
    }

    return CGlobalExport{
        .value = null,
        .type = .I32,
        .mut = .Immutable,
    };
}

export fn bb_func_handle_isvalid(c_handle: CFuncHandle) bool {
    return c_handle.index != INVALID_FUNC_INDEX;
}

// NOTE: Zig expects this function to be present during linking, which would be fine if zig linked
// this code, but when linking with the MSVC compiler, the compiler runtime doesn't provide this
// function. Manually defining it here ensures the linker error gets resolved.
fn ___chkstk_ms() callconv(.Naked) void {}

comptime {
    @export(___chkstk_ms, .{ .name = "___chkstk_ms", .linkage = .Weak });
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local helpers

fn translateError(err: anyerror) CError {
    switch (err) {
        error.OutOfMemory => return CError.OutOfMemory,
        error.UnlinkableUnknownImport => return CError.UnknownImport,
        error.UnlinkableIncompatibleImportType => return CError.IncompatibleImport,
        else => return CError.Failed,
    }
}
