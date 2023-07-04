const std = @import("std");
const core = @import("core.zig");

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

const CHostFunction = *const fn (userdata: ?*anyopaque, module: *CModuleInstance, params: [*]CVal, returns: [*]CVal) void;

const CImportFunction = extern struct {
    name: ?[*:0]c_char,
    func: ?CHostFunction,
    params: ?[*]CValType,
    num_params: usize,
    returns: ?[*]CValType,
    num_returns: usize,
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

const CValType = enum(c_int) {
    I32,
    I64,
    F32,
    F64,
};

const CVal = extern union {
    i32_val: i32,
    i64_val: i64,
    f32_val: f32,
    f64_val: f64,
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
    var module: ?*core.ModuleInstance = null;
    if (definition.module != null) {
        var module_definition = @ptrCast(*core.ModuleDefinition, @alignCast(@alignOf(core.ModuleDefinition), definition.module.?));

        var allocator = cffi_gpa.allocator();
        module = allocator.create(core.ModuleInstance) catch null;

        if (module) |m| {
            m.* = core.ModuleInstance.init(module_definition, allocator);
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

    var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), instance.module.?));
    module.deinit();

    var allocator = cffi_gpa.allocator();
    allocator.destroy(module);
}

export fn bb_module_instance_instantiate(instance: *CModuleInstance, opts: CModuleInstanceInstantiateOpts) CError {
    if (instance.module != null) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), instance.module.?));

        // var allocator = cffi_gpa.allocator();

        // var packages = std.ArrayList(core.ModuleImportPackage).init(allocator);
        // defer {
        //     for (packages.items) |package| {
        //         package.deinit();
        //     }
        //     packages.deinit();
        // }

        // const c_packages: []const CImportPackage = std.mem.sliceTo(opts.packages, 0);

        // packages.ensureTotalCapacityPrecise(c_packages.len) catch |err| return translateError(err);
        // for (c_packages) |c_package| {
        //     const package_name: []const u8 = if (c_package.name != null) std.mem.sliceTo(c_package.name.?, 0) else "";

        //     var package = core.ModuleImportPackage.init(package_name, null, c_package.userdata, allocator) catch |err| return translateError(err);

        //     const c_functions = std.mem.sliceTo(c_package.functions, 0);
        //     for (c_functions) |c_function| {
        //         const function_name: []const u8 = if (c_function.name != null) std.mem.sliceTo(c_function.name.?, 0) else return CError.InvalidParameter;

        //         const c_param_types: CValType = std.mem.sliceTo(c_function.params, 0);
        //         const c_return_types: CValType = std.mem.sliceTo(c_function.returns, 0);

        //         const total_vals = c_param_types.len + c_return_types.len;
        //         var valtypes = allocator.alloc(core.ValType, total_vals) catch |err| return translateError(err);
        //         defer allocator.free(valtypes);
        //         var params_types_temp = valtypes[0..c_param_types.len];
        //         var returns_types_temp = valtypes[c_param_types.len..];

        //         // TODO
        //         // translateCValTypeToValType(c_param_types, params_types_temp);
        //         // translateCValTypeToValType(c_return_types, returns_types_temp);

        //         package.addHostFunction(function_name, params_types_temp, returns_types_temp, callback) catch |err| return translateError(err);
        //     }

        //     packages.append(package) catch |err| return translateError(err);
        // }

        const opts_translated = core.ModuleInstantiateOpts{
            .imports = undefined, // TODO
            // .imports = imports.items,
            .enable_debug = opts.enable_debug,
        };

        if (module.instantiate(opts_translated)) {
            return CError.Ok;
        } else |err| {
            return translateError(err);
        }
    }

    return CError.Failed;
}

export fn bb_module_instance_invoke(instance: *CModuleInstance, func_name: ?[*:0]const c_char, params: ?[*]CVal, num_params: usize, returns: ?[*]CVal, num_returns: usize, opts: CModuleInstanceInvokeOpts) CError {
    if (instance.module != null and func_name != null and (num_params == 0 or params != null) and (num_returns == 0 or returns != null)) {
        var module = @ptrCast(*core.ModuleInstance, @alignCast(@alignOf(core.ModuleInstance), instance.module.?));

        var allocator = cffi_gpa.allocator();
        const func_name_slice = std.mem.sliceTo(func_name.?, 0);

        // var params_slice: []CVal = if (params == null) &[_]CVal{} else params.?[0..num_params];
        // var returns_slice: []CVal = if (returns == null) &[_]CVal{} else returns.?[0..num_returns];

        if (module.module_def.getFuncExportInfo(func_name_slice)) |func_info| {
            _ = func_info;
            const total_vals = num_params + num_returns;
            var vals = allocator.alloc(core.Val, total_vals) catch |err| return translateError(err);
            defer allocator.free(vals);
            var params_temp = vals[0..num_params];
            var returns_temp = vals[num_params..];

            // TODO
            // if (translateCValToVal(func_info.params, params_slice, params_temp) == false) {
            //     return CError.InvalidParameter;
            // }

            const invoke_opts = core.ModuleInstance.InvokeOpts{
                .trap_on_start = opts.trap_on_start,
            };

            if (module.invoke(func_name_slice, params_temp, returns_temp, invoke_opts)) {
                // TODO
                // if (translateValToCVal(func_info.returns, returns_temp, returns_slice)) {
                //     return CError.Ok;
                // } else {
                //     unreachable;
                // }
            } else |err| {
                return translateError(err);
            }
        }
    }

    return CError.InvalidParameter;
}

export fn bb_module_instance_resume(instance: *CModuleInstance, returns: ?[*]CVal, num_returns: usize) CError {
    _ = instance;
    _ = returns;
    _ = num_returns;
    return CError.Failed;
}

export fn bb_module_instance_step(instance: *CModuleInstance, returns: ?[*]CVal, num_returns: usize) CError {
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

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local helpers

fn translateError(err: anyerror) CError {
    switch (err) {
        error.OutOfMemory => return CError.OutOfMemory,
        else => return CError.Failed,
    }
}

// fn translateCValTypeToValType(c_valtypes: []const CValType, valtypes: []core.ValType) bool {
//     std.debug.assert(c_valtypes.len == valtypes.len);
//     for (c_valtypes) |valtype, i| {
//         switch (valtype) {
//             .I32 => valtypes[i] = .I32,
//             .I64 => valtypes[i] = .I64,
//             .F32 => valtypes[i] = .F32,
//             .F64 => valtypes[i] = .F64,
//             else => return false, // TODO log unsupported type
//         }
//     }

//     return true;
// }

// fn translateCValToVal(valtypes: []const core.ValType, c_vals: []const CVal, vals: []core.Val) bool {
//     std.debug.assert(valtypes.len == vals.len);
//     std.debug.assert(valtypes.len == c_vals.len);
//     for (valtypes) |valtype, i| {
//         switch (valtype) {
//             .I32 => vals[i].I32 = c_vals[i].i32_val,
//             .I64 => vals[i].I64 = c_vals[i].i64_val,
//             .F32 => vals[i].F32 = c_vals[i].f32_val,
//             .F64 => vals[i].F64 = c_vals[i].f64_val,
//             else => return false, // TODO log unsupported type
//         }
//     }

//     return true;
// }

// fn translateValToCVal(valtypes: []const core.ValType, vals: []const core.Val, c_vals: []CVal) bool {
//     std.debug.assert(valtypes.len == vals.len);
//     std.debug.assert(valtypes.len == c_vals.len);
//     for (valtypes) |valtype, i| {
//         switch (valtype) {
//             .I32 => c_vals[i].i32_val = vals[i].I32,
//             .I64 => c_vals[i].i64_val = vals[i].I64,
//             .F32 => c_vals[i].f32_val = vals[i].F32,
//             .F64 => c_vals[i].f64_val = vals[i].F64,
//             else => return false, // TODO log unsupported type
//         }
//     }

//     return true;
// }

// fn cvaltypeToValtype(c_valtype: CValType) !core.ValType {
//     switch (c_valtype) {
//         .I32 => return .I32,
//         .I64 => return .I64,
//         .F32 => return .F32,
//         .F64 => return .F64,
//         else => return error.Unsupported, // TODO log unsupported type
//     }
// }

// fn translateCValToVal(c_val: CVal, valtype: core.ValType) !core.Val {
//     switch (valtype) {
//         .I32 => return c_val[i].i32_val,
//         .I64 => return c_val[i].i64_val,
//         .F32 => return c_val[i].f32_val,
//         .F64 => return c_val[i].f64_val,
//         else => return error.Unsupported, // TODO log unsupported type
//     }
// }

// fn translateValToCVal(val: core.Val, valtype: core.ValType) !CVal {
//     switch (valtype) {
//         .I32 => return val.I32,
//         .I64 => return val.I64,
//         .F32 => return val.F32,
//         .F64 => return val.F64,
//         else => return error.Unsupported, // TODO log unsupported type
//     }
// }

// const CHostFunctionContext = struct {
//     package_context: *CHostPackageContext,
//     func_def: *const FunctionTypeDefinition,
//     callback: CHostFunction,
// };

// const CHostPackageContext = struct {
//     functions: std.ArrayList(CHostFunctionContext),
//     userdata: ?*anyopaque,
// };

// fn cStackTranslateHelper(comptime in_type: type, out_type: type, _translate_func: *const fn (in_type) out_type) type {
//     return struct {
//         const Self = @This();
//         const translate_func = _translate_func;

//         out: [16]out_type = undefined,

//         fn translateTypes(self: *Self, in: []const in_type) ![]const out_type {
//             if (in.len > self.out.len) {
//                 return error.Unsupported;
//             }
//             for (in) |v, i| {
//                 self.out[i] = try translate_func(v);
//             }
//             return self.out[0..in.len];
//         }

//         fn translateVals(self: *Self, in: []const in_type, in_type: []const ValType) ![]const out_type {
//             if (in.len > self.out.len) {
//                 return error.Unsupported;
//             }
//             for (in) |v, i| {
//                 self.out[i] = try translate_func(v, in_type[i]);
//             }
//             return self.out[0..in.len];
//         }
//     };
// }

// const CValToValHelper = cStackTranslateHelper(CVal, Val, cvalToVal);
// const ValToCValHelper = cStackTranslateHelper(Val, CVal, cvalToVal);

// fn hostFunctionShim(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
//     const context = @ptrCast(*const CHostFunctionContext, @alignCast(@alignOf(CHostFunctionContext), userdata));
//     var c_module = CModuleInstance{
//         .module = module,
//     };

//     const param_types = c_context.

//     var c_params_translate = ValToCValHelper{};
//     var c_returns_translate = CValToValHelper{};

//     var c_params = c_params_translate.translateVals(, param_types);
//     var c_returns = ;
//     context.callback(context.package_context.userdata, c_module, c_params, c_returns);
// }
