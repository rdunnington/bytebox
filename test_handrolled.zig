




// const FunctionBuilder = struct {
//     const Self = @This();

//     instructions: std.ArrayList(u8),

//     fn init(allocator: *std.mem.Allocator) Self {
//         var self = Self{
//             .instructions = std.ArrayList(u8).init(allocator),
//         };
//         return self;
//     }

//     fn deinit(self:*Self) void {
//         self.instructions.deinit();
//     }

//     fn add(self: *Self, comptime opcode:Opcode) !void {
//         if (instructionHasImmediates(opcode)) {
//             unreachable; // Use one of the other add functions.
//         }

//         var writer = self.instructions.writer();
//         try writer.writeByte(@enumToInt(opcode));
//     }

//     fn addBlock(self: *Self, comptime opcode: Opcode, comptime blocktype: BlockType, param: anytype) !void {
//         switch (opcode) {
//             .Block => {},
//             .Loop => {},
//             .If => {},
//             else => unreachable, // opcode must be Block or Loop
//         }

//         var writer = self.instructions.writer();
//         try writer.writeByte(@enumToInt(opcode));

//         switch (blocktype) {
//             .Void => {
//                 try writer.writeByte(k_block_type_void_sentinel_byte);
//             },
//             .ValType => {
//                 if (@TypeOf(param) != ValType) {
//                     unreachable; // When adding a Val block, you must specify which ValType it is.
//                 }
//                 try writer.writeByte(@enumToInt(param));
//             },
//             .TypeIndex => {
//                 var index:i33 = param;
//                 try std.leb.writeILEB128(writer, index);
//             }
//         }
//     }

//     fn addBranch(self: *Self, comptime branch: Opcode, label_data: anytype) !void {
//         var writer = self.instructions.writer();

//         switch (branch) {
//             .Branch => {
//                 try writer.writeByte(@enumToInt(Opcode.Branch));
//                 try std.leb.writeULEB128(writer, @intCast(u32, label_data));
//             },
//             .Branch_If => {
//                 try writer.writeByte(@enumToInt(Opcode.Branch_If));
//                 try std.leb.writeULEB128(writer, @intCast(u32, label_data));
//             },
//             .Branch_Table => {
//                 // expects label_data to be a struct {table: []u32, fallback_id:u32}
//                 try writer.writeByte(@enumToInt(Opcode.Branch_Table));
//                 try std.leb.writeULEB128(writer, @intCast(u32, label_data.table.len));
//                 var index: u32 = 0;
//                 while (index < label_data.table.len) {
//                     var label_id: u32 = label_data.table[index];
//                     try std.leb.writeULEB128(writer, @intCast(u32, label_id));
//                     index += 1;
//                 }
//                 try std.leb.writeULEB128(writer, @intCast(u32, label_data.fallback_id));
//             },
//             else => {
//                 unreachable; // pass Branch, Branch_If, or Branch_Table
//             }
//         }
//     }

//     fn addConstant(self: *Self, comptime T: type, value: T) !void {
//         var writer = self.instructions.writer();
//         switch (T) {
//             i32 => { 
//                 try writer.writeByte(@enumToInt(Opcode.I32_Const));
//                 try std.leb.writeILEB128(writer, value); 
//             },
//             // TODO i64, f32, f64
//             else => unreachable,
//         }
//     }

//     fn addVariable(self: *Self, opcode:Opcode, index:u32) !void {
//         switch (opcode) {
//             .Local_Get => {},
//             .Local_Set => {},
//             .Local_Tee => {},
//             .Global_Get => {},
//             .Global_Set => {},
//             else => unreachable,
//         }

//         var writer = self.instructions.writer();
//         try writer.writeByte(@enumToInt(opcode));
//         try std.leb.writeULEB128(writer, index);
//     }
// };

// const ModuleBuilder = struct {
//     const Self = @This();

//     const WasmFunction = struct {
//         exportName: std.ArrayList(u8),
//         ftype: FunctionTypeDefinition,
//         locals: std.ArrayList(ValType),
//         instructions: std.ArrayList(u8),
//     };

//     const WasmGlobal = struct {
//         exportName: std.ArrayList(u8),
//         type: ValType,
//         mut: GlobalMut,
//         initInstructions: std.ArrayList(u8),
//     };

//     allocator: *std.mem.Allocator,
//     functions: std.ArrayList(WasmFunction),
//     tables: std.ArrayList(Table),
//     globals: std.ArrayList(WasmGlobal),
//     wasm: std.ArrayList(u8),
//     needsRebuild: bool = true,

//     fn init(allocator: *std.mem.Allocator) Self {
//         return Self{
//             .allocator = allocator,
//             .functions = std.ArrayList(WasmFunction).init(allocator),
//             .tables = std.ArrayList(Table).init(allocator),
//             .globals = std.ArrayList(WasmGlobal).init(allocator),
//             .wasm = std.ArrayList(u8).init(allocator),
//         };
//     }

//     fn deinit(self: *Self) void {
//         for (self.functions.items) |*func| {
//             func.exportName.deinit();
//             func.ftype.types.deinit();
//             func.locals.deinit();
//             func.instructions.deinit();
//         }
//         self.functions.deinit();
//         self.tables.deinit();

//         for (self.globals.items) |*global| {
//             global.exportName.deinit();
//             global.initInstructions.deinit();
//         }
//         self.globals.deinit();

//         self.wasm.deinit();
//     }

//     fn addFunc(self: *Self, exportName: ?[]const u8, params: []const ValType, returns: []const ValType, locals: []const ValType, instructions: []const u8) !void {
//         var f = WasmFunction{
//             .exportName = std.ArrayList(u8).init(self.allocator),
//             .ftype = FunctionTypeDefinition{
//                 .types = std.ArrayList(ValType).init(self.allocator),
//                 .numParams = @intCast(u32, params.len),
//             },
//             .locals = std.ArrayList(ValType).init(self.allocator),
//             .instructions = std.ArrayList(u8).init(self.allocator),
//         };
//         errdefer f.exportName.deinit();
//         errdefer f.ftype.types.deinit();
//         errdefer f.locals.deinit();
//         errdefer f.instructions.deinit();

//         if (exportName) |name| {
//             try f.exportName.appendSlice(name);
//         }
//         try f.ftype.types.appendSlice(params);
//         try f.ftype.types.appendSlice(returns);
//         try f.locals.appendSlice(locals);
//         try f.instructions.appendSlice(instructions);

//         try self.functions.append(f);

//         self.needsRebuild = true;
//     }

//     fn addGlobal(self: *Self, exportName: ?[]const u8, valtype: ValType, mut: GlobalMut, initOpts:GlobalValueInitOptions) !void {
//         var g = WasmGlobal{
//             .exportName = std.ArrayList(u8).init(self.allocator),
//             .type = valtype,
//             .mut = mut,
//             .initInstructions = std.ArrayList(u8).init(self.allocator),
//         };
//         errdefer g.exportName.deinit();
//         errdefer g.initInstructions.deinit();

//         if (exportName) |name| {
//             try g.exportName.appendSlice(name);
//         }

//         switch (initOpts) {
//             .Value => |v| {
//                 var writer = g.initInstructions.writer();
//                 try writeTypedValue(v, writer);
//                 try writer.writeByte(@enumToInt(Opcode.End));
//             },
//         }

//         try self.globals.append(g);

//         self.needsRebuild = true;
//     }

//     fn addTable(self: *Self, reftype: ValType, min: u32, max: ?u32) !void {
//         if (self.tables.items.len > 0) {
//             return error.OneTableAllowed;
//         }
//         if (reftype.isRefType() == false) {
//             return error.TypeMismatch;
//         }

//         try self.tables.append(Table{
//             .refs = undefined,
//             .reftype = reftype,
//             .min = min,
//             .max = max,
//         });
//     }

//     fn build(self: *Self) !void {
//         self.wasm.clearRetainingCapacity();

//         // dedupe function types and sort for quick lookup
//         const FunctionTypeSetType = std.HashMap(*FunctionTypeDefinition, *FunctionTypeDefinition, FunctionTypeContext, std.hash_map.default_max_load_percentage);
//         var functionTypeSet = FunctionTypeSetType.init(self.allocator);
//         defer functionTypeSet.deinit();

//         // std.debug.print("self.functions.items: {s}\n", .{self.functions.items});
//         for (self.functions.items) |*func| {
//             _ = try functionTypeSet.getOrPut(&func.ftype);
//         }

//         var functionTypesSorted = std.ArrayList(*FunctionTypeDefinition).init(self.allocator);
//         defer functionTypesSorted.deinit();
//         try functionTypesSorted.ensureTotalCapacity(functionTypeSet.count());
//         {
//             var iter = functionTypeSet.iterator();
//             var entry = iter.next();
//             while (entry != null) {
//                 if (entry) |e| {
//                     try functionTypesSorted.append(e.key_ptr.*);
//                     entry = iter.next();
//                 }
//             }
//         }
//         std.sort.sort(*FunctionTypeDefinition, functionTypesSorted.items, FunctionTypeContext{}, FunctionTypeContext.less);

//         // Serialize header and sections

//         const header = [_]u8{
//             0x00, 0x61, 0x73, 0x6D,
//             0x01, 0x00, 0x00, 0x00,
//         };

//         try self.wasm.appendSlice(&header);

//         var sectionBytes = std.ArrayList(u8).init(self.allocator);
//         defer sectionBytes.deinit();
//         try sectionBytes.ensureTotalCapacity(1024 * 4);

//         var scratchBuffer = std.ArrayList(u8).init(self.allocator);
//         defer scratchBuffer.deinit();
//         try scratchBuffer.ensureTotalCapacity(1024);

//         const sectionsToSerialize = [_]Section{ .FunctionType, .Function, .Table, .Global, .Export, .Code };
//         for (sectionsToSerialize) |section| {
//             sectionBytes.clearRetainingCapacity();
//             var writer = sectionBytes.writer();
//             switch (section) {
//                 .FunctionType => {
//                     try std.leb.writeULEB128(writer, @intCast(u32, functionTypesSorted.items.len));
//                     for (functionTypesSorted.items) |funcType| {
//                         try writer.writeByte(k_function_type_sentinel_byte);

//                         var params = funcType.getParams();
//                         var returns = funcType.getReturns();

//                         try std.leb.writeULEB128(writer,  @intCast(u32, params.len));
//                         for (params) |v| {
//                             try writer.writeByte(@enumToInt(v));
//                         }
//                         try std.leb.writeULEB128(writer,  @intCast(u32, returns.len));
//                         for (returns) |v| {
//                             try writer.writeByte(@enumToInt(v));
//                         }
//                     }
//                 },
//                 .Function => {
//                     try std.leb.writeULEB128(writer,  @intCast(u32, self.functions.items.len));
//                     for (self.functions.items) |*func| {
//                         var context = FunctionTypeContext{};
//                         var index: ?usize = std.sort.binarySearch(*FunctionTypeDefinition, &func.ftype, functionTypesSorted.items, context, FunctionTypeContext.order);
//                         try std.leb.writeULEB128(writer,  @intCast(u32, index.?));
//                     }
//                 },
//                 .Table => {
//                     try std.leb.writeULEB128(writer, @intCast(u32, self.tables.items.len));
//                     for (self.tables.items) |table| {
//                         try writer.writeByte(@enumToInt(table.reftype));

//                         if (table.max != null) {
//                             try writer.writeByte(1);
//                         } else {
//                             try writer.writeByte(0);
//                         }

//                         try std.leb.writeULEB128(writer, @intCast(u32, table.min));
//                         if (table.max) |max| {
//                             try std.leb.writeULEB128(writer, @intCast(u32, max));
//                         }
//                     }
//                 },
//                 .Global => {
//                     try std.leb.writeULEB128(writer, @intCast(u32, self.globals.items.len));
//                     for (self.globals.items) |global| {
//                         try writer.writeByte(@enumToInt(global.type));
//                         try writer.writeByte(@enumToInt(global.mut));
//                         _ = try writer.write(global.initInstructions.items);
//                     }
//                 },
//                 .Export => {
//                     var num_exports:u32 = 0;
//                     for (self.functions.items) |func| {
//                         if (func.exportName.items.len > 0) {
//                             num_exports += 1;
//                         }
//                     }
//                     for (self.globals.items) |global| {
//                         if (global.exportName.items.len > 0) {
//                             num_exports += 1;
//                         }
//                     }

//                     try std.leb.writeULEB128(writer, @intCast(u32, num_exports));

//                     for (self.functions.items) |func, i| {
//                         if (func.exportName.items.len > 0) {
//                             try std.leb.writeULEB128(writer,  @intCast(u32, func.exportName.items.len));
//                             _ = try writer.write(func.exportName.items);
//                             try writer.writeByte(@enumToInt(ExportType.Function));
//                             try std.leb.writeULEB128(writer,  @intCast(u32, i));
//                         }
//                     }
//                     for (self.globals.items) |global, i| {
//                         if (global.exportName.items.len > 0) {
//                             try std.leb.writeULEB128(writer,  @intCast(u32, global.exportName.items.len));
//                             _ = try writer.write(global.exportName.items);
//                             try writer.writeByte(@enumToInt(ExportType.Global));
//                             try std.leb.writeULEB128(writer,  @intCast(u32, i));
//                         }
//                     }
//                 },
//                 .Code => {
//                     try std.leb.writeULEB128(writer,  @intCast(u32, self.functions.items.len));
//                     for (self.functions.items) |func| {
//                         var scratchWriter = scratchBuffer.writer();
//                         defer scratchBuffer.clearRetainingCapacity();

//                         try std.leb.writeULEB128(scratchWriter,  @intCast(u32, func.locals.items.len));
//                         for (func.locals.items) |local| {
//                             try scratchWriter.writeByte(@enumToInt(local));
//                         }
//                         _ = try scratchWriter.write(func.instructions.items);
//                         try scratchWriter.writeByte(@enumToInt(Opcode.End));

//                         try std.leb.writeULEB128(writer, @intCast(u32, scratchBuffer.items.len));
//                         try sectionBytes.appendSlice(scratchBuffer.items);
//                     }
//                 },
//                 else => { 
//                     unreachable;
//                 }
//             }

//             if (sectionBytes.items.len > 0) {
//                 var wasmWriter = self.wasm.writer();
//                 try wasmWriter.writeByte(@enumToInt(section));
//                 try std.leb.writeULEB128(wasmWriter, @intCast(u32, sectionBytes.items.len));
//                 _ = try wasmWriter.write(sectionBytes.items);
//             }
//         }
//     }

//     fn getWasm(self: *Self) ![]const u8 {
//         if (self.needsRebuild) {
//             try self.build();
//         }

//         return self.wasm.items;
//     }
// };

// fn writeTypedValue(value:Val, writer: anytype) !void {
//     switch (value) {
//         .I32 => |v| {
//             try writer.writeByte(@enumToInt(Opcode.I32_Const));
//             try std.leb.writeILEB128(writer, @intCast(i32, v));
//         },
//         else => unreachable,
//         // .I64 => |v| {
//         //     try writer.writeByte(@enumToInt(Opcode.I64_Const));
//         //     try writer.writeIntBig(i64, v);
//         // },
//         // .F32 => |v| {
//         //     try writer.writeByte(@enumToInt(Opcode.F32_Const));
//         //     try writer.writeIntBig(f32, v);
//         // },
//         // .F64 => |v| {
//         //     try writer.writeByte(@enumToInt(Opcode.F64_Const));
//         //     try writer.writeIntBig(f64, v);
//         // },
//     }
// }
// 
// 
// const TestFunction = struct{
//     bytecode: []const u8,
//     exportName: ?[]const u8 = null,
//     params: ?[]ValType = null,
//     locals: ?[]ValType = null,
//     returns: ?[]ValType = null,
// };

// const TestGlobal = struct {
//     exportName: ?[]const u8,
//     initValue: Val,
//     mut: GlobalMut,
// };

// const TestOptions = struct {
//     startFunctionIndex:u32 = 0,
//     startFunctionParams: ?[]Val = null,
//     functions: [] const TestFunction,
//     globals: ?[]const TestGlobal = null,
// };

// fn testCallFunc(options:TestOptions, expectedReturns:?[]Val) !void {
//     var builder = ModuleBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     for (options.functions) |func|
//     {
//         const params = func.params orelse &[_]ValType{};
//         const locals = func.locals orelse &[_]ValType{};
//         const returns = func.returns orelse &[_]ValType{};

//         try builder.addFunc(func.exportName, params, returns, locals, func.bytecode);
//     }

//     if (options.globals) |globals| {
//         for (globals) |global| {
//             var valtype = std.meta.activeTag(global.initValue);
//             var initOpts = GlobalValueInitOptions{
//                 .Value = global.initValue,
//             };

//             try builder.addGlobal(global.exportName, valtype, global.mut, initOpts);
//         }
//     }

//     const wasm = try builder.getWasm();
//     var vm = try VmState.parseWasm(wasm, .UseExisting, std.testing.allocator);
//     defer vm.deinit();

//     const params = options.startFunctionParams orelse &[_]Val{};

//     var returns = std.ArrayList(Val).init(std.testing.allocator);
//     defer returns.deinit();

//     if (expectedReturns) |expected| {
//         try returns.resize(expected.len);
//     }

//     var name = options.functions[options.startFunctionIndex].exportName orelse "";
//     try vm.callFunc(name, params, returns.items);

//     if (expectedReturns) |expected|
//     {
//         for (expected) |expectedValue, i| {
//             if (std.meta.activeTag(expectedValue) == ValType.I32) {
//                 var result_u32 = @bitCast(u32, returns.items[i].I32);
//                 var expected_u32 = @bitCast(u32, expectedValue.I32);
//                 if (result_u32 != expected_u32) {
//                     std.debug.print("expected: 0x{X}, result: 0x{X}\n", .{ expected_u32, result_u32 });
//                 }                
//             }
//             try std.testing.expect(std.meta.eql(expectedValue, returns.items[i]));
//         }
//     }
// }

// fn testCallFuncI32ParamReturn(bytecode: []const u8, param:i32, expected:i32) !void {
//     var types = [_]ValType{.I32};
//     var functions = [_]TestFunction{
//         .{
//             .bytecode = bytecode,
//             .exportName = "testFunc",
//             .params = &types,
//             .locals = &types,
//             .returns = &types,
//         },
//     };
//     var params = [_]Val{
//         .{.I32 = param}
//     };
//     var opts = TestOptions{
//         .startFunctionParams = &params,
//         .functions = &functions,
//     };
//     var expectedReturns = [_]Val{.{.I32 = expected}};
//     try testCallFunc(opts, &expectedReturns);
// }

// fn testCallFuncI32Return(bytecode: []const u8, expected:i32) !void {
//     var types = [_]ValType{.I32};
//     var functions = [_]TestFunction{
//         .{
//             .bytecode = bytecode,
//             .exportName = "testFunc",
//             .returns = &types,
//         },
//     };
//     var opts = TestOptions{
//         .functions = &functions,
//     };
//     var expectedReturns = [_]Val{.{.I32 = expected}};
//     try testCallFunc(opts, &expectedReturns);
// }

// fn testCallFuncU32Return(bytecode: []const u8, expected:u32) !void {
//     try testCallFuncI32Return(bytecode, @bitCast(i32, expected));
// }

// fn testCallFuncSimple(bytecode: []const u8) !void {
//     var opts = TestOptions{
//         .functions = &[_]TestFunction{
//             .{
//                 .bytecode = bytecode,
//                 .exportName = "testFunc",
//             },
//         },
//     };

//     try testCallFunc(opts, null);
// }

// pub fn printBytecode(label: []const u8, bytecode: []const u8) void {
//     std.debug.print("\n\n{s}: \n\t", .{label});
//     var tab:u32 = 0;
//     for (bytecode) |byte| {
//         if (tab == 4) {
//             std.debug.print("\n\t", .{});
//             tab = 0;
//         }
//         tab += 1;
//         std.debug.print("0x{X:2} ", .{byte});
//     }
//     std.debug.print("\n", .{});
// }

// // test "module builder" {
// //     var builder = ModuleBuilder.init(std.testing.allocator);
// //     defer builder.deinit();

// //     try builder.addFunc("abcd", &[_]ValType{.I64}, &[_]ValType{.I32}, &[_]ValType{ .I32, .I64 }, &[_]u8{ 0x01, 0x01, 0x01, 0x01 });
// //     try builder.addTable(ValType.FuncRef, 32, 64);
// //     try builder.addGlobal("glb1", ValType.I32, GlobalMut.Immutable, GlobalValueInitOptions{.Value = Val{.I32=0x88}});
// //     var wasm = try builder.getWasm();

// //     var expected = std.ArrayList(u8).init(std.testing.allocator);
// //     defer expected.deinit();
// //     try expected.ensureTotalCapacity(1024);

// //     {
// //         var writer = expected.writer();

// //         _ = try writer.write(&[_]u8{0x00, 0x61, 0x73, 0x6D});
// //         try writer.writeIntLittle(u32, 1);
// //         try writer.writeByte(@enumToInt(Section.FunctionType));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x6)); // section size
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num types
// //         try writer.writeByte(k_function_type_sentinel_byte);
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num params
// //         try writer.writeByte(@enumToInt(ValType.I64));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num returns
// //         try writer.writeByte(@enumToInt(ValType.I32));
// //         try writer.writeByte(@enumToInt(Section.Function));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x2)); // section size
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num functions
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x0)); // index to types
// //         try writer.writeByte(@enumToInt(Section.Table));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x5)); // section size
// //         try std.leb.writeULEB128(writer, @intCast(u32, 1)); // num tables
// //         try writer.writeByte(1); // has max
// //         try std.leb.writeULEB128(writer, @intCast(u32, 32)); // min
// //         try std.leb.writeULEB128(writer, @intCast(u32, 64)); // max
// //         try writer.writeByte(@enumToInt(ValType.FuncRef));
// //         try writer.writeByte(@enumToInt(Section.Global));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x7)); // section size
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num globals
// //         try writer.writeByte(@enumToInt(GlobalMut.Immutable));
// //         try writer.writeByte(@enumToInt(ValType.I32));
// //         try writer.writeByte(@enumToInt(Opcode.I32_Const));
// //         try std.leb.writeILEB128(writer, @intCast(i32, 0x88));
// //         try writer.writeByte(@enumToInt(Opcode.End));
// //         try writer.writeByte(@enumToInt(Section.Export));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0xF)); // section size
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x2)); // num exports
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x4)); // size of export name (1)
// //         _ = try writer.write("abcd");
// //         try writer.writeByte(@enumToInt(ExportType.Function));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x0)); // index of export
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x4)); // size of export name (2)
// //         _ = try writer.write("glb1");
// //         try writer.writeByte(@enumToInt(ExportType.Global));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x0)); // index of export
// //         try writer.writeByte(@enumToInt(Section.Code));
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0xA)); // section size
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x1)); // num codes
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x8)); // code size
// //         try std.leb.writeULEB128(writer, @intCast(u32, 0x2)); // num locals
// //         try writer.writeByte(@enumToInt(ValType.I32));
// //         try writer.writeByte(@enumToInt(ValType.I64));
// //         try writer.writeByte(@enumToInt(Opcode.Noop));
// //         try writer.writeByte(@enumToInt(Opcode.Noop));
// //         try writer.writeByte(@enumToInt(Opcode.Noop));
// //         try writer.writeByte(@enumToInt(Opcode.Noop));
// //         try writer.writeByte(@enumToInt(Opcode.End));
// //     }

// //     const areEqual = std.mem.eql(u8, wasm, expected.items);

// //     if (!areEqual) {
// //         printBytecode("expected", expected.items);
// //         printBytecode("actual", wasm);
// //     }

// //     try std.testing.expect(areEqual);
// // }

// test "unreachable" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.add(.Unreachable);

//     var didCatchError:bool = false;
//     var didCatchCorrectError:bool = false;
//     testCallFuncSimple(builder.instructions.items) catch |e| {
//         didCatchError = true;
//         didCatchCorrectError = (e == VMError.Unreachable);
//     };

//     try std.testing.expect(didCatchError);
//     try std.testing.expect(didCatchCorrectError);
// }

// test "noop" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);
//     try builder.add(.Noop);

//     try testCallFuncSimple(builder.instructions.items);
// }

// test "block void" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addBlock(.Block, .Void, .{});
//     try builder.add(.End);
//     try testCallFuncSimple(builder.instructions.items);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, .Void, .{});
//     try builder.addConstant(i32, 0x1337);
//     try builder.add(.End);
//     var didCatchError = false;
//     var didCatchCorrectError = false;
//     testCallFuncSimple(builder.instructions.items) catch |e| {
//         didCatchError = true;
//         didCatchCorrectError = (e == VMError.TypeMismatch);
//     };
//     try std.testing.expect(didCatchError);
// }

// test "block valtypes" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.add(.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.add(.End);
//     var didCatchError = false;
//     var didCatchCorrectError = false;
//     testCallFuncSimple(builder.instructions.items) catch |e| {
//         didCatchError = true;
//         didCatchCorrectError = (e == VMError.TypeMismatch);
//     };
//     try std.testing.expect(didCatchError);
// }

// // test "block typeidx" {
    
// // }

// test "loop" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addBlock(.Block, .Void, .{});
//     try builder.addBlock(.Loop, .Void, .{});
//     try builder.addConstant(i32, 1);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.add(.I32_Add);
//     try builder.addVariable(Opcode.Local_Tee, 0);
//     try builder.addConstant(i32, 10);
//     try builder.add(.I32_NE);
//     try builder.addBranch(Opcode.Branch_If, 0);
//     try builder.add(.End);
//     try builder.add(.End);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try testCallFuncI32ParamReturn(builder.instructions.items, 0, 10);
// }

// test "if-else" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addConstant(i32, 1);
//     try builder.addBlock(.If, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.add(.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0);
//     try builder.addBlock(.If, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x2);
//     try builder.add(Opcode.I32_Mul);
//     try builder.add(.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x1337);
//     try builder.addVariable(Opcode.Local_Set, 0);
//     try builder.addConstant(i32, 1); // take if branch
//     try builder.addBlock(.If, BlockType.ValType, ValType.I32);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.addConstant(i32, 0x2);
//     try builder.add(.I32_Mul);
//     try builder.add(.Else);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.addConstant(i32, 0x2);
//     try builder.add(.I32_Add);
//     try builder.add(.End);
//     try testCallFuncI32ParamReturn(builder.instructions.items, 0, 0x266E);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x1337);
//     try builder.addVariable(Opcode.Local_Set, 0);
//     try builder.addConstant(i32, 0); // take else branch
//     try builder.addBlock(.If, BlockType.ValType, ValType.I32);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.addConstant(i32, 0x2);
//     try builder.add(.I32_Mul);
//     try builder.add(.Else);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.addConstant(i32, 0x2);
//     try builder.add(.I32_Add);
//     try builder.add(.End);
//     try testCallFuncI32ParamReturn(builder.instructions.items, 0, 0x1339);
// }

// test "branch" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addBlock(.Block, BlockType.Void, .{});
//     try builder.addBranch(Opcode.Branch, 0);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try testCallFuncSimple(builder.instructions.items);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.addBranch(Opcode.Branch, 0);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.addBranch(Opcode.Branch, 2);
//     try builder.add(Opcode.End);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try builder.add(Opcode.Drop);
//     try builder.addConstant(i32, 0xDEAD);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.addBranch(Opcode.Branch, 1);
//     try builder.add(Opcode.End);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try builder.add(Opcode.Drop);
//     try builder.addConstant(i32, 0xDEAD);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0xDEAD);
// }

// test "branch_if" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addBlock(.Block, BlockType.Void, .{});
//     try builder.addConstant(i32, 1);
//     try builder.addBranch(Opcode.Branch_If, 0);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try testCallFuncSimple(builder.instructions.items);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0x1);
//     try builder.addBranch(Opcode.Branch_If, 0);
//     try builder.add(Opcode.Drop);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0x0);
//     try builder.addBranch(Opcode.Branch_If, 0);
//     try builder.add(Opcode.Drop);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0xBEEF);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0x1);
//     try builder.addBranch(Opcode.Branch_If, 2);
//     try builder.add(Opcode.End);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try builder.add(Opcode.Drop);
//     try builder.addConstant(i32, 0xDEAD);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0x1);
//     try builder.addBranch(Opcode.Branch_If, 1);
//     try builder.add(Opcode.End);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try builder.add(Opcode.Drop);
//     try builder.addConstant(i32, 0xDEAD);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0xDEAD);
// }

// test "branch_table" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     const branch_table = [_]u32{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1};

//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0xDEAD);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.addBranch(Opcode.Branch_Table, .{.table = &branch_table, .fallback_id = 0});
//     try builder.add(Opcode.Return);
//     try builder.add(Opcode.End); // 0
//     try builder.addConstant(i32, 0x1337);
//     try builder.add(Opcode.Return);
//     try builder.add(Opcode.End); // 1
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.Return);
//     try builder.add(Opcode.End); // 2

//     var branch_to_take:i32 = 0;
//     while (branch_to_take <= branch_table.len) { // go beyond the length of the table to test the fallback
//         const expected:i32 = if (@mod(branch_to_take, 2) == 0) 0x1337 else 0xBEEF;
//         try testCallFuncI32ParamReturn(builder.instructions.items, branch_to_take, expected);
//         branch_to_take += 1;
//     }
// }

// test "return" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     // factorial
//     // fn f(v:u32) u32 {
//     //     if (v == 1) {
//     //          return 0x1337;
//     //     } else if (v == 2) {
//     //          return 0xBEEF;
//     //     } else {
//     //          return 0x12345647;
//     //     }
//     // }

//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addConstant(i32, 0x1337);
//     try builder.add(Opcode.Return);
//     try builder.add(Opcode.End);
//     try builder.addConstant(i32, 0xDEAD);
//     try builder.add(Opcode.End);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.End);
//     try builder.addConstant(i32, 0xFACE);
//     try builder.add(Opcode.End);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);
// }

// test "call and return" {
//     var builder0 = FunctionBuilder.init(std.testing.allocator);
//     var builder1 = FunctionBuilder.init(std.testing.allocator);
//     var builder2 = FunctionBuilder.init(std.testing.allocator);
//     defer builder0.deinit();
//     defer builder1.deinit();
//     defer builder2.deinit();

//     try builder0.addVariable(Opcode.Local_Get, 0);
//     try builder0.addConstant(i32, 0x421);
//     try builder0.add(Opcode.I32_Add); // 0x42 + 0x421 = 0x463
//     try builder0.addConstant(i32, 0x01);
//     try builder0.add(Opcode.Call);

//     try builder1.addVariable(Opcode.Local_Get, 0);
//     try builder1.addConstant(i32, 0x02);
//     try builder1.add(Opcode.I32_Mul); // 0x463 * 2 = 0x8C6
//     try builder1.addConstant(i32, 0x02);
//     try builder1.add(Opcode.Call);
//     try builder0.add(Opcode.Return);

//     try builder2.addVariable(Opcode.Local_Get, 0);
//     try builder2.addConstant(i32, 0xBEEF);
//     try builder2.add(Opcode.I32_Add); // 0x8C6 + 0xBEEF = 0xC7B5
//     try builder2.add(Opcode.Return);

//     var types = [_]ValType{.I32};
//     var functions = [_]TestFunction{
//         .{
//             .exportName = "testFunc",
//             .bytecode = builder0.instructions.items,
//             .params = &types,
//             .locals = &types,
//             .returns = &types,
//         },
//         .{
//             .bytecode = builder1.instructions.items,
//             .params = &types,
//             .locals = &types,
//             .returns = &types,
//         },
//         .{
//             .bytecode = builder2.instructions.items,
//             .params = &types,
//             .locals = &types,
//             .returns = &types,
//         },
//     };
//     var params = [_]Val{.{.I32 = 0x42}};
//     var opts = TestOptions{
//         .functions = &functions,
//         .startFunctionParams = &params,
//     };
//     var expected = [_]Val{.{.I32 = 0xC7B5}};

//     try testCallFunc(opts, &expected);
// }

// test "call recursive" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     // factorial
//     // fn f(v:u32) u32 {
//     //     if (v == 1) {
//     //         return 1;
//     //     } else {
//     //         var vv = f(v - 1);
//     //         return v * vv;
//     //     }
//     // }

//     try builder.addBlock(.Block, BlockType.ValType, ValType.I32);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.addConstant(i32, 1);
//     try builder.add(Opcode.I32_Eq);
//     try builder.addBranch(Opcode.Branch_If, 0); // return v if 
//     try builder.addConstant(i32, 1);
//     try builder.add(Opcode.I32_Sub);
//     try builder.addConstant(i32, 0); // call func at index 0 (recursion)
//     try builder.add(Opcode.Call);
//     try builder.addVariable(Opcode.Local_Get, 0);
//     try builder.add(Opcode.I32_Mul);
//     try builder.add(Opcode.End);
//     try testCallFuncI32ParamReturn(builder.instructions.items, 5, 120); // 5! == 120
// }

// test "drop" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.add(Opcode.Drop);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);
// }

// test "select" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.addConstant(i32, 0xFF); //nonzero should pick val1
//     try builder.add(Opcode.Select);
//     try testCallFuncI32Return(builder.instructions.items, 0x1337);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0xBEEF);
//     try builder.addConstant(i32, 0x0); //zero should pick val2
//     try builder.add(Opcode.Select);
//     try testCallFuncI32Return(builder.instructions.items, 0xBEEF);
// }

// test "local_get" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addVariable(Opcode.Local_Get, 0);
//     try testCallFuncI32ParamReturn(builder.instructions.items, 0x1337, 0x1337);
// }

// test "local_set" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addConstant(i32, 0x1337);
//     try builder.addConstant(i32, 0x1336);
//     try builder.addConstant(i32, 0x1335);
//     try builder.addVariable(Opcode.Local_Set, 0); // pop stack values and set in local
//     try builder.addVariable(Opcode.Local_Set, 0);
//     try builder.addVariable(Opcode.Local_Set, 0);
//     try builder.addVariable(Opcode.Local_Get, 0); // push local value onto stack, should be 1337 since it was the first pushed

//     var types = [_]ValType{.I32};
//     var emptyTypes = [_]ValType{};
//     var params = [_]Val{};
//     var opts = TestOptions{
//         .startFunctionParams = &params,
//         .functions = &[_]TestFunction{
//             .{
//                 .exportName = "testFunc",
//                 .bytecode = builder.instructions.items,
//                 .params = &emptyTypes,
//                 .locals = &types,
//                 .returns = &types,
//             }
//         },
//     };
//     var expected = [_]Val{.{.I32 = 0x1337}};

//     try testCallFunc(opts, &expected);
// }

// test "local_tee" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addConstant(i32, 0x1337);
//     try builder.addVariable(Opcode.Local_Tee, 0); // put value in locals but also leave it on the stack
//     try builder.addVariable(Opcode.Local_Get, 0); // push the same value back onto the stack
//     try builder.add(Opcode.I32_Add);

//     var types = [_]ValType{.I32};
//     var emptyTypes = [_]ValType{};
//     var params = [_]Val{};
//     var opts = TestOptions{
//         .startFunctionParams = &params,
//         .functions = &[_]TestFunction{
//             .{
//                 .exportName = "testFunc",
//                 .bytecode = builder.instructions.items,
//                 .params = &emptyTypes,
//                 .locals = &types,
//                 .returns = &types,
//             }
//         },
//     };
//     var expected = [_]Val{.{.I32 = 0x266E}};

//     try testCallFunc(opts, &expected);
// }

// test "global_get" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addVariable(Opcode.Global_Get, 0x0);

//     var returns = [_]ValType{.I32};
//     var functions = [_]TestFunction{
//         .{
//             .exportName = "testFunc",
//             .bytecode = builder.instructions.items,
//             .returns = &returns,
//         }
//     };
//     var globals = [_]TestGlobal {
//         .{
//             .exportName = "abcd",
//             .initValue = Val{.I32 = 0x1337},
//             .mut = GlobalMut.Immutable,
//         },
//     };
//     var options = TestOptions{
//         .functions = &functions,
//         .globals = &globals,
//     };
//     var expected = [_]Val{.{.I32 = 0x1337}};
//     try testCallFunc(options, &expected);
// }

// test "global_set" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();

//     try builder.addConstant(i32, 0x1337);
//     try builder.addVariable(Opcode.Global_Set, 0);
//     try builder.addVariable(Opcode.Global_Get, 0);

//     var returns = [_]ValType{.I32};
//     var globals = [_]TestGlobal {
//         .{
//             .exportName = null,
//             .initValue = Val{.I32 = 0x0},
//             .mut = GlobalMut.Mutable,
//         },
//     };
//     var functions = &[_]TestFunction{
//         .{
//             .exportName = "testFunc",
//             .bytecode = builder.instructions.items,
//             .returns = &returns,
//         }
//     };
//     var options = TestOptions{
//         .functions = functions,
//         .globals = &globals,
//     };
//     var expected = [_]Val{.{.I32 = 0x1337}};

//     try testCallFunc(options, &expected);

//     globals[0].mut = GlobalMut.Immutable;
//     var didCatchError = false;
//     var didCatchCorrectError = false;
//     testCallFunc(options, &expected) catch |err| {
//         didCatchError = true;
//         didCatchCorrectError = (err == VMError.AttemptToSetImmutable);
//     };

//     try std.testing.expect(didCatchError);
//     try std.testing.expect(didCatchCorrectError);
// }

// test "i32_eqz" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0);
//     try builder.add(Opcode.I32_Eqz);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 1);
//     try builder.add(Opcode.I32_Eqz);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);
// }

// test "i32_eq" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0);
//     try builder.addConstant(i32, 0);
//     try builder.add(Opcode.I32_Eq);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0);
//     try builder.addConstant(i32, -1);
//     try builder.add(Opcode.I32_Eq);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);
// }

// test "i32_ne" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0);
//     try builder.addConstant(i32, 0);
//     try builder.add(Opcode.I32_NE);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0);
//     try builder.addConstant(i32, -1);
//     try builder.add(Opcode.I32_NE);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);
// }

// test "i32_lt_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_LT_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_LT_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);
// }

// test "i32_lt_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600); // 0xFFFFFA00 when unsigned
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_LT_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_LT_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);
// }

// test "i32_gt_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_GT_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_GT_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);
// }

// test "i32_gt_u" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600); // 0xFFFFFA00 when unsigned
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_GT_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_GT_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);
// }

// test "i32_le_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_LE_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_LE_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_LE_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);
// }

// test "i32_le_u" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_LE_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_LE_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_LE_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);
// }

// test "i32_ge_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_GE_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_GE_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_GE_S);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);
// }

// test "i32_ge_u" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x800);
//     try builder.add(Opcode.I32_GE_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, 0x800);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_GE_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x0);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, -0x600);
//     try builder.add(Opcode.I32_GE_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x1);
// }

// test "i32_add" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0x100001);
//     try builder.addConstant(i32, 0x000201);
//     try builder.add(Opcode.I32_Add);
//     try testCallFuncI32Return(builder.instructions.items, 0x100202);
// }

// test "i32_sub" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0x100001);
//     try builder.addConstant(i32, 0x000201);
//     try builder.add(Opcode.I32_Sub);
//     try testCallFuncI32Return(builder.instructions.items, 0xFFE00);
// }

// test "i32_mul" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0x200);
//     try builder.addConstant(i32, 0x300);
//     try builder.add(Opcode.I32_Mul);
//     try testCallFuncI32Return(builder.instructions.items, 0x60000);
// }

// test "i32_div_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x200);
//     try builder.add(Opcode.I32_Div_S);
//     var expected:i32 = -3;
//     try testCallFuncU32Return(builder.instructions.items, @bitCast(u32, expected));
// }

// test "i32_div_u" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x600); // 0xFFFFFA00 unsigned
//     try builder.addConstant(i32, 0x200);
//     try builder.add(Opcode.I32_Div_U);
//     try testCallFuncU32Return(builder.instructions.items, 0x7FFFFD);
// }

// test "i32_rem_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x666);
//     try builder.addConstant(i32, 0x200);
//     try builder.add(Opcode.I32_Rem_S);
//     try testCallFuncI32Return(builder.instructions.items, -0x66);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, -0x600);
//     try builder.addConstant(i32, 0x200);
//     try builder.add(Opcode.I32_Rem_S);
//     try testCallFuncI32Return(builder.instructions.items, 0);
// }

// test "i32_rem_u" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x666); // 0xFFFFF99A unsigned
//     try builder.addConstant(i32, 0x200);
//     try builder.add(Opcode.I32_Rem_U);
//     try testCallFuncI32Return(builder.instructions.items, 0x19A);

//     builder.instructions.clearRetainingCapacity();
//     try builder.addConstant(i32, -0x800);
//     try builder.addConstant(i32, 0x200);
//     try builder.add(Opcode.I32_Rem_U);
//     try testCallFuncI32Return(builder.instructions.items, 0);
// }

// test "i32_and" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0x0FFFFFFF);
//     try builder.addConstant(i32, 0x01223344);
//     try builder.add(Opcode.I32_And);
//     try testCallFuncI32Return(builder.instructions.items, 0x01223344);
// }

// test "i32_or" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0x0F00FF00);
//     try builder.addConstant(i32, 0x01223344);
//     try builder.add(Opcode.I32_Or);
//     try testCallFuncI32Return(builder.instructions.items, 0x0F22FF44);
// }

// test "i32_xor" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, 0x0F0F0F0F);
//     try builder.addConstant(i32, 0x70F00F0F);
//     try builder.add(Opcode.I32_Xor);
//     try testCallFuncI32Return(builder.instructions.items, 0x7FFF0000);
// }

// test "i32_shl" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
//     try builder.addConstant(i32, 0x2);
//     try builder.add(Opcode.I32_Shl);
//     try testCallFuncU32Return(builder.instructions.items, 0x40404);
// }

// test "i32_shr_s" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
//     try builder.addConstant(i32, 0x1);
//     try builder.add(Opcode.I32_Shr_S);
//     try testCallFuncU32Return(builder.instructions.items, 0xC0008080);
// }

// test "i32_shr_u" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
//     try builder.addConstant(i32, 0x1);
//     try builder.add(Opcode.I32_Shr_U);
//     try testCallFuncU32Return(builder.instructions.items, 0x40008080);
// }

// test "i32_rotl" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
//     try builder.addConstant(i32, 0x2);
//     try builder.add(Opcode.I32_Rotl);
//     try testCallFuncU32Return(builder.instructions.items, 0x00040406);
// }

// test "i32_rotr" {
//     var builder = FunctionBuilder.init(std.testing.allocator);
//     defer builder.deinit();
//     try builder.addConstant(i32, -0x7FFEFEFF); // 0x80010101 unsigned
//     try builder.addConstant(i32, 0x2);
//     try builder.add(Opcode.I32_Rotr);
//     try testCallFuncU32Return(builder.instructions.items, 0x60004040);
// }
