const def = @import("definition.zig");
const vm = @import("vm_stack.zig");
pub const wasi = @import("wasi.zig");

pub const i8x16 = def.i8x16;
pub const u8x16 = def.u8x16;
pub const i16x8 = def.i16x8;
pub const u16x8 = def.u16x8;
pub const i32x4 = def.i32x4;
pub const u32x4 = def.u32x4;
pub const i64x2 = def.i64x2;
pub const u64x2 = def.u64x2;
pub const f32x4 = def.f32x4;
pub const f64x2 = def.f64x2;
pub const v128 = def.v128;

pub const MalformedError = def.MalformedError;
pub const ValidationError = def.ValidationError;

pub const FunctionExport = def.FunctionExport;
pub const FunctionHandle = def.FunctionHandle;
pub const FunctionHandleType = def.FunctionHandleType;
pub const GlobalDefinition = def.GlobalDefinition;
pub const GlobalMut = def.GlobalMut;
pub const Limits = def.Limits;
pub const ModuleDefinition = def.ModuleDefinition;
pub const ModuleDefinitionOpts = def.ModuleDefinitionOpts;
pub const TaggedVal = def.TaggedVal;
pub const Val = def.Val;
pub const ValType = def.ValType;

pub const UnlinkableError = vm.UnlinkableError;
pub const UninstantiableError = vm.UninstantiableError;
pub const ExportError = vm.ExportError;
pub const TrapError = vm.TrapError;

pub const DebugTrace = vm.DebugTrace;
pub const GlobalImport = vm.GlobalImport;
pub const GlobalInstance = vm.GlobalInstance;
pub const MemoryImport = vm.MemoryImport;
pub const MemoryInstance = vm.MemoryInstance;
pub const ModuleImportPackage = vm.ModuleImportPackage;
pub const ModuleInstance = vm.ModuleInstance;
pub const ModuleInstantiateOpts = vm.ModuleInstantiateOpts;
pub const TableImport = vm.TableImport;
pub const TableInstance = vm.TableInstance;
pub const WasmMemoryExternal = vm.WasmMemoryExternal;
pub const WasmMemoryFreeFunction = vm.WasmMemoryFreeFunction;
pub const WasmMemoryResizeFunction = vm.WasmMemoryResizeFunction;
