const std = @import("std");
const assert = std.debug.assert;

const builtin = @import("builtin");

const AllocError = std.mem.Allocator.Error;

const common = @import("common.zig");
const StableArray = common.StableArray;

const opcodes = @import("opcode.zig");
const Opcode = opcodes.Opcode;
const WasmOpcode = opcodes.WasmOpcode;

const def = @import("definition.zig");
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
const BlockImmediates = def.BlockImmediates;
const BranchTableImmediates = def.BranchTableImmediates;
const CallIndirectImmediates = def.CallIndirectImmediates;
const ConstantExpression = def.ConstantExpression;
const DataDefinition = def.DataDefinition;
const ElementDefinition = def.ElementDefinition;
const ElementMode = def.ElementMode;
const FunctionDefinition = def.FunctionDefinition;
const FunctionExport = def.FunctionExport;
const FunctionHandle = def.FunctionHandle;
const FunctionHandleType = def.FunctionHandleType;
const FunctionTypeDefinition = def.FunctionTypeDefinition;
const GlobalDefinition = def.GlobalDefinition;
const GlobalMut = def.GlobalMut;
const IfImmediates = def.IfImmediates;
const ImportNames = def.ImportNames;
const Instruction = def.Instruction;
const Limits = def.Limits;
const MemoryDefinition = def.MemoryDefinition;
const MemoryOffsetAndLaneImmediates = def.MemoryOffsetAndLaneImmediates;
const ModuleDefinition = def.ModuleDefinition;
const NameCustomSection = def.NameCustomSection;
const TableDefinition = def.TableDefinition;
const TablePairImmediates = def.TablePairImmediates;
const Val = def.Val;
const ValType = def.ValType;
const TaggedVal = def.TaggedVal;

// High-level strategy:
// 1. Transform the ModuleDefinition's bytecode into a sea-of-nodes type of IR.
// 2. Perform constant folding, and other peephole optimizations.
// 3. Perform register allocation
// 4. Generate new bytecode
// 5. Implement the runtime instructions for the register-based bytecode

const IRNode = struct {
    instruction_index: usize,
    edges_in: ?[*]*IRNode,
    edges_in_count: u32,
    edges_out: ?[*]*IRNode,
    edges_out_count: u32,

    fn create(mir: *ModuleIR, index: usize) AllocError!*IRNode {
        var node: *IRNode = mir.ir.addOne() catch return AllocError.OutOfMemory;
        node.* = IRNode{
            .instruction_index = index,
            .edges_in = null,
            .edges_in_count = 0,
            .edges_out = null,
            .edges_out_count = 0,
        };
        return node;
    }

    fn deinit(node: IRNode, allocator: std.mem.Allocator) void {
        if (node.edges_in) |e| allocator.free(e[0..node.edges_in_count]);
        if (node.edges_out) |e| allocator.free(e[0..node.edges_out_count]);
    }

    fn instruction(node: IRNode, module_def: ModuleDefinition) *Instruction {
        return &module_def.code.instructions.items[node.instruction_index];
    }

    fn edgesIn(node: IRNode) []*IRNode {
        return if (node.edges_in) |e| e[0..node.edges_in_count] else &[0]*IRNode{};
    }

    fn edgesOut(node: IRNode) []*IRNode {
        return if (node.edges_out) |e| e[0..node.edges_out_count] else &[0]*IRNode{};
    }

    const EdgeDirection = enum {
        In,
        Out,
    };

    fn pushEdges(node: *IRNode, comptime direction: EdgeDirection, edges: []*IRNode, allocator: std.mem.Allocator) AllocError!void {
        const existing = if (direction == .In) node.edgesIn() else node.edgesOut();
        var new = try allocator.alloc(*IRNode, existing.len + edges.len);
        @memcpy(new[0..existing.len], existing);
        @memcpy(new[existing.len .. existing.len + edges.len], edges);
        if (existing.len > 0) {
            allocator.free(existing);
        }
        switch (direction) {
            .In => {
                node.edges_in = new.ptr;
                node.edges_in_count = @intCast(new.len);
            },
            .Out => {
                node.edges_out = new.ptr;
                node.edges_out_count = @intCast(new.len);
            },
        }
    }
};

const IRFunction = struct {
    def_index: usize,
    ir_root: *IRNode,

    fn definition(func: IRFunction, module_def: ModuleDefinition) *FunctionDefinition {
        return &module_def.functions.items[func.def_index];
    }

    fn dumpVizGraph(func: IRFunction, path: []u8, module_def: ModuleDefinition, allocator: std.mem.Allocator) !void {
        var graph_txt = std.ArrayList(u8).init(allocator);
        defer graph_txt.deinit();
        try graph_txt.ensureTotalCapacity(1024 * 16);

        var writer = graph_txt.writer();
        _ = try writer.write("digraph {\n");

        var nodes = std.ArrayList(*const IRNode).init(allocator);
        defer nodes.deinit();
        try nodes.ensureTotalCapacity(1024);
        nodes.appendAssumeCapacity(func.ir_root);

        var visited = std.AutoHashMap(*IRNode, void).init(allocator);
        defer visited.deinit();
        try visited.put(func.ir_root, {});

        while (nodes.items.len > 0) {
            const n: *const IRNode = nodes.pop();
            const instruction = n.instruction(module_def);
            const opcode: Opcode = instruction.opcode;

            var label_buffer: [256]u8 = undefined;

            const label = switch (opcode) {
                .I32_Const => std.fmt.bufPrint(&label_buffer, "{}", .{instruction.immediate.ValueI32}) catch unreachable,
                .Local_Get, .Local_Set, .Local_Tee => std.fmt.bufPrint(&label_buffer, "{}", .{instruction.immediate.Index}) catch unreachable,
                else => &[0]u8{},
            };

            if (label.len > 0) {
                try writer.print("\"{*}\" [label=\"{}: {s}\"]\n", .{ n, opcode, label });
            } else {
                try writer.print("\"{*}\" [label=\"{}\"]\n", .{ n, opcode });
            }

            for (n.edgesOut()) |e| {
                try writer.print("\"{*}\" -> \"{*}\"\n", .{ n, e });

                if (!visited.contains(e)) {
                    try nodes.append(e);
                    try visited.put(e, {});
                }
            }

            for (n.edgesIn()) |e| {
                if (!visited.contains(e)) {
                    try nodes.append(e);
                    try visited.put(e, {});
                }
            }
        }

        _ = try writer.write("}\n");

        try std.fs.cwd().writeFile(path, graph_txt.items);
    }
};

const ModuleIR = struct {
    const IntermediateCompileData = struct {
        const UniqueValueToIRNodeMap = std.HashMap(TaggedVal, *IRNode, TaggedVal.HashMapContext, std.hash_map.default_max_load_percentage);

        allocator: std.mem.Allocator,

        // This stack is a record of the nodes to push values onto the stack. If an instruction would push
        // multiple values onto the stack, it would be in this list as many times as values it pushed. Note
        // that we don't have to do any type checking here because the module has already been validated.
        nodes_value_stack: std.ArrayList(*IRNode),

        // This is a bit weird - since the Local_* instructions serve to just manipulate the locals into the stack,
        // we need a way to represent what's in the locals slot as an SSA node. This array lets us do that. We also
        // reuse the Local_Get instructions to indicate the "initial value" of the slot. Since our IRNode only stores
        // indices to instructions, we'll just lazily set these when they're fetched for the first time.
        locals: std.ArrayList(?*IRNode),

        // Lets us collapse multiple const IR nodes with the same type/value into a single one
        unique_constants: UniqueValueToIRNodeMap,

        fn init(allocator: std.mem.Allocator) IntermediateCompileData {
            return IntermediateCompileData{
                .allocator = allocator,
                .nodes_value_stack = std.ArrayList(*IRNode).init(allocator),
                .locals = std.ArrayList(?*IRNode).init(allocator),
                .unique_constants = UniqueValueToIRNodeMap.init(allocator),
            };
        }

        fn warmup(self: *IntermediateCompileData, func_def: FunctionDefinition, module_def: ModuleDefinition) AllocError!void {
            try self.locals.appendNTimes(null, func_def.numParamsAndLocals(module_def));
        }

        fn reset(self: *IntermediateCompileData) void {
            self.nodes_value_stack.clearRetainingCapacity();
            self.locals.clearRetainingCapacity();
            self.unique_constants.clearRetainingCapacity();
        }

        fn deinit(self: *IntermediateCompileData) void {
            self.nodes_value_stack.deinit();
            self.locals.deinit();
            self.unique_constants.deinit();
        }

        fn consumeValueStackNodes(self: *IntermediateCompileData, consumer: *IRNode, num_nodes: usize) AllocError!void {
            var edges_buffer: [8]*IRNode = undefined;
            var edges = edges_buffer[0..num_nodes];
            for (edges) |*e| {
                e.* = self.nodes_value_stack.pop();
            }
            try consumer.pushEdges(.In, edges, self.allocator);
            for (edges) |e| {
                var consumer_edges = [_]*IRNode{consumer};
                try e.pushEdges(.Out, &consumer_edges, self.allocator);
            }
            try self.nodes_value_stack.append(consumer);
        }

        fn foldConstant(self: *IntermediateCompileData, mir: *ModuleIR, comptime valtype: ValType, instruction_index: usize, instruction: Instruction) AllocError!*IRNode {
            var val: TaggedVal = undefined;
            val.type = valtype;
            val.val = switch (valtype) {
                .I32 => Val{ .I32 = instruction.immediate.ValueI32 },
                .I64 => Val{ .I64 = instruction.immediate.ValueI64 },
                .F32 => Val{ .F32 = instruction.immediate.ValueF32 },
                .F64 => Val{ .F64 = instruction.immediate.ValueF64 },
                .V128 => Val{ .V128 = instruction.immediate.ValueVec },
                else => @compileError("Unsupported const instruction"),
            };

            var res = try self.unique_constants.getOrPut(val);
            if (res.found_existing == false) {
                var node = try IRNode.create(mir, instruction_index);
                res.value_ptr.* = node;
            }
            try self.nodes_value_stack.append(res.value_ptr.*);
            return res.value_ptr.*;
        }
    };

    allocator: std.mem.Allocator,
    module_def: *const ModuleDefinition,
    functions: std.ArrayList(IRFunction),
    ir: StableArray(IRNode),

    fn init(allocator: std.mem.Allocator, module_def: *const ModuleDefinition) ModuleIR {
        return ModuleIR{
            .allocator = allocator,
            .module_def = module_def,
            .functions = std.ArrayList(IRFunction).init(allocator),
            .ir = StableArray(IRNode).init(1024 * 1024 * 8),
        };
    }

    fn deinit(mir: *ModuleIR) void {
        mir.functions.deinit();
        for (mir.ir.items) |node| {
            node.deinit(mir.allocator);
        }
        mir.ir.deinit();
    }

    fn compile(mir: *ModuleIR) AllocError!void {
        var compile_data = IntermediateCompileData.init(mir.allocator);
        defer compile_data.deinit();

        for (0..mir.module_def.functions.items.len) |i| {
            std.debug.print("mir.module_def.functions.items.len: {}, i: {}\n\n", .{ mir.module_def.functions.items.len, i });
            try mir.compileFunc(i, &compile_data);

            compile_data.reset();
        }
    }

    fn compileFunc(mir: *ModuleIR, index: usize, compile_data: *IntermediateCompileData) AllocError!void {
        const UniqueValueToIRNodeMap = std.HashMap(TaggedVal, *IRNode, TaggedVal.HashMapContext, std.hash_map.default_max_load_percentage);

        const Helpers = struct {
            fn opcodeHasDefaultIRMapping(opcode: Opcode) bool {
                return switch (opcode) {
                    .Noop,
                    .Drop,
                    .I32_Const,
                    .I64_Const,
                    .F32_Const,
                    .F64_Const,
                    .Local_Get,
                    .Local_Set,
                    .Local_Tee,
                    => false,
                    else => true,
                };
            }
        };

        const func: *const FunctionDefinition = &mir.module_def.functions.items[index];
        const func_type: *const FunctionTypeDefinition = func.typeDefinition(mir.module_def.*);

        std.debug.print("compiling func index {}\n", .{index});

        try compile_data.warmup(func.*, mir.module_def.*);

        var locals = compile_data.locals.items; // for convenience later

        // Lets us collapse multiple const IR nodes with the same type/value into a single one
        var unique_constants = UniqueValueToIRNodeMap.init(mir.allocator);
        defer unique_constants.deinit();

        const instructions: []Instruction = func.instructions(mir.module_def.*);
        if (instructions.len == 0) {
            std.log.warn("Skipping function with no instructions (index {}).", .{index});
            return;
        }

        var ir_root: ?*IRNode = null;

        for (instructions, 0..) |instruction, local_instruction_index| {
            const instruction_index = func.instructions_begin + local_instruction_index;

            var node: ?*IRNode = null;
            if (Helpers.opcodeHasDefaultIRMapping(instruction.opcode)) {
                node = try IRNode.create(mir, instruction_index);
            }

            std.debug.print("opcode: {}\n", .{instruction.opcode});

            switch (instruction.opcode) {
                // .Loop => {
                //     instruction.
                // },
                // .If => {},
                .Return => {
                    try compile_data.consumeValueStackNodes(node.?, func_type.getReturns().len);
                },
                .Drop => {
                    _ = compile_data.nodes_value_stack.pop();
                },
                .I32_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(mir, .I32, instruction_index, instruction);
                },
                .I64_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(mir, .I64, instruction_index, instruction);
                },
                .F32_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(mir, .F32, instruction_index, instruction);
                },
                .F64_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(mir, .F64, instruction_index, instruction);
                },
                .I32_Eq,
                .I32_NE,
                .I32_LT_S,
                .I32_LT_U,
                .I32_GT_S,
                .I32_GT_U,
                .I32_LE_S,
                .I32_LE_U,
                .I32_GE_S,
                .I32_GE_U,
                .I32_Add,
                .I32_Sub,
                .I32_Mul,
                .I32_Div_S,
                .I32_Div_U,
                .I32_Rem_S,
                .I32_Rem_U,
                .I32_And,
                .I32_Or,
                .I32_Xor,
                .I32_Shl,
                .I32_Shr_S,
                .I32_Shr_U,
                .I32_Rotl,
                .I32_Rotr,
                // TODO add a lot more of these simpler opcodes
                => {
                    try compile_data.consumeValueStackNodes(node.?, 2);
                },
                .I32_Eqz,
                .I32_Clz,
                .I32_Ctz,
                .I32_Popcnt,
                .I32_Extend8_S,
                .I32_Extend16_S,
                => {
                    try compile_data.consumeValueStackNodes(node.?, 1);
                },
                .Local_Get => {
                    assert(node == null);

                    const local: *?*IRNode = &locals[instruction.immediate.Index];
                    if (local.* == null) {
                        local.* = try IRNode.create(mir, instruction_index);
                    }
                    node = local.*;
                    try compile_data.nodes_value_stack.append(node.?);
                },
                .Local_Set => {
                    assert(node == null);

                    var n: *IRNode = compile_data.nodes_value_stack.pop();
                    locals[instruction.immediate.Index] = n;
                },
                .Local_Tee => {
                    assert(node == null);
                    var n: *IRNode = compile_data.nodes_value_stack.items[compile_data.nodes_value_stack.items.len - 1];
                    locals[instruction.immediate.Index] = n;
                },
                else => {
                    std.log.warn("skipping node {}", .{instruction.opcode});
                },
            }

            if (ir_root == null) {
                ir_root = node;
            }
        }

        try mir.functions.append(IRFunction{
            .def_index = index,
            .ir_root = ir_root.?,
        });
    }
};

pub const RegisterVM = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RegisterVM {
        return RegisterVM{ .allocator = allocator };
    }

    pub fn compile(vm: *RegisterVM, module_def: ModuleDefinition) AllocError!void {
        var mir = ModuleIR.init(vm.allocator, module_def);
        defer mir.deinit();

        try mir.compile();
    }

    // pub fn instantiate() {}
    // pub fn invoke() {}
};

test "ir1" {
    const filename =
        \\E:\Dev\third_party\zware\test\fact.wasm
        // \\E:\Dev\zig_projects\bytebox\test\wasm\i32\i32.0.wasm
    ;
    var allocator = std.testing.allocator;

    var cwd = std.fs.cwd();
    var wasm_data: []u8 = try cwd.readFileAlloc(allocator, filename, 1024 * 1024 * 128);
    defer allocator.free(wasm_data);

    const module_def_opts = def.ModuleDefinitionOpts{
        .debug_name = std.fs.path.basename(filename),
    };
    var module_def = ModuleDefinition.init(allocator, module_def_opts);
    defer module_def.deinit();

    try module_def.decode(wasm_data);

    var mir = ModuleIR.init(allocator, &module_def);
    defer mir.deinit();
    try mir.compile();
    for (mir.functions.items, 0..) |func, i| {
        var viz_path_buffer: [256]u8 = undefined;
        const path_format =
            \\E:\Dev\zig_projects\bytebox\viz\viz_{}.txt
        ;
        const viz_path = std.fmt.bufPrint(&viz_path_buffer, path_format, .{i}) catch unreachable;
        std.debug.print("gen graph for func {}\n", .{i});
        try func.dumpVizGraph(viz_path, module_def, std.testing.allocator);
    }
}
