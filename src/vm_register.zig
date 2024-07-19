const std = @import("std");
const assert = std.debug.assert;

const builtin = @import("builtin");
const config = @import("config");

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
const BlockType = def.BlockType;
const BlockTypeValue = def.BlockTypeValue;
const BlockImmediates = def.BlockImmediates;
const BranchTableImmediates = def.BranchTableImmediates;
const CallIndirectImmediates = def.CallIndirectImmediates;
const ConstantExpression = def.ConstantExpression;
const DataDefinition = def.DataDefinition;
const ElementDefinition = def.ElementDefinition;
const ElementMode = def.ElementMode;
const FunctionImportDefinition = def.FunctionImportDefinition;
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
const InstructionImmediates = def.InstructionImmediates;
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

const inst = @import("instance.zig");
const TrapError = inst.TrapError;
const VM = inst.VM;
const ModuleInstance = inst.ModuleInstance;
const InvokeOpts = inst.InvokeOpts;
const ResumeInvokeOpts = inst.ResumeInvokeOpts;
const DebugTrapInstructionMode = inst.DebugTrapInstructionMode;
const ModuleInstantiateOpts = inst.ModuleInstantiateOpts;
const DebugTrace = inst.DebugTrace;

const INVALID_INSTRUCTION_INDEX: u32 = std.math.maxInt(u32);

const endian_native = builtin.cpu.arch.endian();

// High-level strategy:
// 1. Transform the ModuleDefinition's bytecode into a sea-of-nodes type of IR.
// 2. Perform constant folding, and other peephole optimizations.
// 3. Perform register allocation
// 4. Generate new bytecode
// 5. Implement the runtime instructions for the register-based bytecode

const IRNodeType = enum(u8) {
    Start,
    Stop,
    Phi,
    Region,
    Instruction,
};

comptime {
    std.debug.assert(@sizeOf(IRNode) == 32);
}

const IRNode = struct {
    type: IRNodeType,
    data: union {
        None: void,
        Instruction: u32, // index into ModuleDefintion instruction array
    },
    edges_in: ?[*]*IRNode,
    edges_in_count: u16,
    edges_out: ?[*]*IRNode,
    edges_out_count: u16,

    fn create(comptime node_type: IRNodeType, compiler: *FunctionCompiler) AllocError!*IRNode {
        comptime switch (node_type) {
            .Instruction => unreachable, // use createInstruction() for this node type
            else => {},
        };

        const node: *IRNode = compiler.ir.addOne() catch return AllocError.OutOfMemory;
        node.* = IRNode{
            .type = node_type,
            .data = .{
                .None = {},
            },
            .edges_in = null,
            .edges_in_count = 0,
            .edges_out = null,
            .edges_out_count = 0,
        };
        return node;
    }

    fn createInstruction(instruction_index: u32, compiler: *FunctionCompiler) AllocError!*IRNode {
        const node: *IRNode = compiler.ir.addOne() catch return AllocError.OutOfMemory;
        node.* = IRNode{
            .type = .Instruction,
            .data = .{
                .Instruction = instruction_index,
            },
            // .opcode = compiler.module_def.code.instructions.items[instruction_index].opcode,
            // .is_phi = false,
            // .instruction_index = instruction_index,
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
        std.debug.assert(node.type == .Instruction);
        return &module_def.code.instructions.items[node.data.Instruction];
    }

    fn opcode(node: IRNode, module_def: ModuleDefinition) Opcode {
        std.debug.assert(node.type == .Instruction);
        return node.instruction(module_def).opcode;
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

    const EdgeIterFilter = enum {
        Control,
        Data,
    };

    const EdgeIter = struct {
        module_def: *const ModuleDefinition,
        edges: []*IRNode,
        filter: EdgeIterFilter,
        index: u32,

        fn next(self: *EdgeIter) ?*IRNode {
            while (true) {
                if (self.index < self.edges.len) {
                    const node = self.edges[self.index];
                    self.index += 1;

                    const is_control = node.isControl(self.module_def.*);
                    if (self.filter == .Control and is_control) {
                        return node;
                    } else if (self.filter == .Data and is_control == false) {
                        return node;
                    }
                } else {
                    break;
                }
            }

            return null;
        }
    };

    fn edgesFilter(node: IRNode, comptime direction: EdgeDirection, module_def: *const ModuleDefinition, filter: EdgeIterFilter) EdgeIter {
        const edges = switch (direction) {
            .In => node.edgesIn(),
            .Out => node.edgesOut(),
        };
        return EdgeIter{
            .module_def = module_def,
            .edges = edges,
            .filter = filter,
            .index = 0,
        };
    }

    fn pushEdge(node: *IRNode, comptime direction: EdgeDirection, edge: *IRNode, module_def: ModuleDefinition, allocator: std.mem.Allocator) AllocError!void {
        var consumer_edges = [_]*IRNode{edge};
        try node.pushEdges(direction, &consumer_edges, module_def, allocator);
    }

    fn pushEdges(node: *IRNode, comptime direction: EdgeDirection, edges: []const *IRNode, module_def: ModuleDefinition, allocator: std.mem.Allocator) AllocError!void {
        std.debug.assert(edges.len > 0);

        switch (node.type) {
            .Start => {
                std.debug.assert(direction == .Out);
                std.debug.assert(edges.len == 1);
                std.debug.assert(edges[0].isControl(module_def));
            },
            .Stop => {
                std.debug.assert(direction == .In);
                for (edges) |e| {
                    std.debug.assert(e.isControl(module_def));
                }
            },
            .Phi => {
                switch (direction) {
                    .In => {
                        for (edges) |e| {
                            std.debug.assert(!e.isControl(module_def));
                        }
                    },
                    .Out => {
                        // make sure there's only one Region node for out edges
                        if (edges[0].type == .Region) {
                            for (node.edgesOut()) |phi_out_edge| {
                                std.debug.assert(phi_out_edge.type != .Region);
                            }
                        }
                    },
                }
            },
            .Region => {
                // TODO
            },
            .Instruction => {},
        }

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

    var pretty_print_buffer: [1024]u8 = undefined;
    fn prettyPrint(node: *const IRNode, module_def: ModuleDefinition) []const u8 {
        var buffer: []u8 = &pretty_print_buffer;
        var details: []u8 = &[_]u8{};
        if (node.type == .Instruction) {
            const op = node.opcode(module_def);
            details = std.fmt.bufPrint(buffer, " {}", .{op}) catch unreachable;
            buffer = buffer[details.len..];
        }
        return std.fmt.bufPrint(buffer, "0x{x} ({}{s})", .{ @intFromPtr(node), node.type, details }) catch unreachable;
    }

    // fn hasSideEffects(node: *IRNode) bool {
    //     // We define a side-effect instruction as any that could affect the Store or control flow
    //     return switch (node.opcode) {
    //         .Call => true,
    //         else => false,
    //     };
    // }

    fn isControl(node: *IRNode, module_def: ModuleDefinition) bool {
        return switch (node.type) {
            .Start,
            .Stop,
            .Region,
            => true,
            .Instruction => switch (node.opcode(module_def)) {
                .If,
                .IfNoElse,
                .Else,
                .End,
                .Return,
                .Branch,
                .Branch_If,
                .Branch_Table,
                => true,
                else => false,
            },
            else => false,
        };
    }

    // a node that has no out edges to instructions with side effects or control flow
    // fn isIsland(node: *IRNode, unvisited: *std.ArrayList(*IRNode)) AllocError!bool {
    //     if (node.opcode == .Return) {
    //         return false;
    //     }

    //     unvisited.clearRetainingCapacity();

    //     for (node.edgesOut()) |edge| {
    //         try unvisited.append(edge);
    //     }

    //     while (unvisited.items.len > 0) {
    //         var next: *IRNode = unvisited.pop();
    //         if (next.opcode == .Return or next.hasSideEffects() or node.isControl()) {
    //             return false;
    //         }
    //         for (next.edgesOut()) |edge| {
    //             try unvisited.append(edge);
    //         }
    //     }

    //     unvisited.clearRetainingCapacity();

    //     return true;
    // }
};

const RegisterSlots = struct {
    const Slot = struct {
        node: ?*IRNode,
        prev: ?u32,
    };

    slots: std.ArrayList(Slot),
    num_reserved: u32,
    num_unique: u32,
    last_free: ?u32,

    fn init(allocator: std.mem.Allocator) RegisterSlots {
        return RegisterSlots{
            .slots = std.ArrayList(Slot).init(allocator),
            .num_reserved = 0,
            .num_unique = 0,
            .last_free = null,
        };
    }

    fn deinit(self: *RegisterSlots) void {
        self.slots.deinit();
    }

    fn reserve(self: *RegisterSlots, count: u32) AllocError!void {
        std.debug.assert(self.slots.items.len == 0);
        std.debug.assert(self.num_reserved == 0);

        self.num_reserved = count;
        // TODO don't actually allocate memory, just simulate it
        try self.slots.appendNTimes(Slot{ .node = null, .prev = null }, count);
    }

    // fn getOrAlloc(self: *RegisterSlots, node: *IRNode) AllocError!u32 {
    //     return switch (node.opcode) {
    //             .Local_Get => {
    //                 const local_index = node.immediate.Index;
    //                 std.debug.assert(local_index < self.num_locals);
    //                 return local_index;
    //             }
    //             .Local_Tee => unreachable,
    //             else => self.alloc(node),
    //         },
    //     }
    //     // for (self.slots.items, 0..) |slot, i| { // TODO make this lookup better
    //     //     if (slot.node == node) {
    //     //         return @intCast(i);
    //     //     }
    //     // }
    // }

    fn alloc(self: *RegisterSlots, node: *IRNode) AllocError!u32 {
        if (self.last_free == null) {
            std.debug.assert(self.slots.items.len < std.math.maxInt(u32));

            self.last_free = @intCast(self.slots.items.len);
            try self.slots.append(Slot{
                .node = null,
                .prev = null,
            });

            if (self.num_unique < self.last_free.?) {
                self.num_unique = self.last_free.?;
            }
        }

        const index = self.last_free.?;
        var slot: *Slot = &self.slots.items[index];
        self.last_free = slot.prev;
        slot.node = node;
        slot.prev = null;

        // std.debug.print("pushed node {*} with opcode {} to index {}\n", .{ node, node.opcode, index });

        return index;
    }

    fn freeAt(self: *RegisterSlots, index: u32) void {
        // Reserved registers are not allowed to be used by general-purpose instructions. They're only for
        // use by Local_* and Return.
        if (index >= self.num_reserved) {
            var slot: *Slot = &self.slots.items[index];
            // std.debug.assert(slot.node == node);

            slot.node = null;
            slot.prev = self.last_free;
            self.last_free = index;
        }

        // std.debug.print("attempting to free node {*} with opcode {} at index {}: {}\n", .{ node, node.opcode, index, succes });
    }
};

const FunctionIR = struct {
    def_index: usize,
    type_def_index: usize,
    start: *IRNode,
    stop: *IRNode,

    // TODO call this from the compiler compile function, have the compile function take instructions and local_types arrays passed down from module instantiate
    // TODO ensure callsites pass a scratch allocator
    fn codegen(func: FunctionIR, store: *FunctionStore, compile_data: *IntermediateCompileData, module_def: ModuleDefinition, scratch_allocator: std.mem.Allocator) AllocError!void {
        std.debug.print("==== CODEGEN: regalloc ====\n", .{});

        // allocate register slots for each node.
        var register_slots = RegisterSlots.init(scratch_allocator); // TODO move this into IntermediateCompileData?
        defer register_slots.deinit();

        const func_def: *const FunctionDefinition = &module_def.functions.items[func.def_index];
        const func_type: *const FunctionTypeDefinition = &module_def.types.items[func.type_def_index];
        const num_locals: u32 = @intCast(func_def.locals.items.len);
        const num_params: u32 = @intCast(func_type.getParams().len);
        const num_returns: u32 = @intCast(func_type.getReturns().len);

        // control nodes are explored via depth-first search to ensure local calulations can reuse
        // the same registers
        var visit_stack_control_nodes = std.ArrayList(*IRNode).init(scratch_allocator); // TODO determine if we really need a stack (e.g. if depth ever goes over 1)
        defer visit_stack_control_nodes.deinit();
        try visit_stack_control_nodes.append(func.stop);

        // we need to visit non-control nodes in breadth-first order to efficiently allocate
        // registers - if a full branch was regalloced, there would be registers allocated
        // to nodes much higher up the branch that could be reused by calulations lower down
        var visit_queue = std.ArrayList(*IRNode).init(scratch_allocator);
        defer visit_queue.deinit();

        var visited = std.AutoHashMap(*IRNode, void).init(scratch_allocator);
        defer visited.deinit();

        {
            // general regalloc algorithm: (DOES NOT HANDLE multiple return points yet)
            // * Reserve registers for function locals (params + local variables)
            // * Run a breadth-first traversal of the graph. Push root node (return) goes on first.
            // * Pop a node off the visit queue
            //   * Free output registers
            //   * Allocate registers for each consumed input
            //   * push input nodes onto the visit queue

            // First reserve space for params, locals, and return values. Return values use the same
            // slots that params do.
            const num_reserved_registers: u32 = @max(num_returns, num_params + num_locals);
            try register_slots.reserve(num_reserved_registers);

            while (visit_queue.items.len > 0 or visit_stack_control_nodes.items.len > 0) {
                var node: *IRNode = undefined;
                if (visit_queue.items.len > 0) {
                    node = visit_queue.orderedRemove(0); // visit the graph in breadth-first order (FIFO queue)
                    std.debug.print("\tdata node {s}\n", .{node.prettyPrint(module_def)});
                } else {
                    node = visit_stack_control_nodes.pop();
                    std.debug.print("\tcontrol node {s}\n", .{node.prettyPrint(module_def)});
                }

                // var node: *IRNode = visit_queue.orderedRemove(0); // visit the graph in breadth-first order (FIFO queue)
                try visited.put(node, {});

                const output_edges: []*IRNode = node.edgesOut();

                // mark output node slots as free if they've all been visited. This is safe because the dataflow graph flows one way and the
                // output can't be reused higher up in the graph
                var did_visit_all_outputs: bool = true;
                for (output_edges) |output_node| {
                    if (!visited.contains(output_node)) {
                        did_visit_all_outputs = false;
                        break;
                    }
                }

                if (did_visit_all_outputs) {
                    // free this node's register slot so they can be used by another instruction
                    // TODO handle multiple outputs
                    if (compile_data.register_map.get(node)) |index| {
                        std.debug.print("\t\tfreeing output slot at: {}\n", .{index});
                        register_slots.freeAt(index);
                    }
                }

                const input_nodes: []*IRNode = node.edgesIn();

                // allocate registers for this instruction
                if (node.type == .Instruction) {
                    const opcode = node.opcode(module_def);

                    if (opcode == .Return or (opcode == .End and func.stop.edgesIn()[0] == node)) { // check if End is a returning node
                        var iter = node.edgesFilter(.In, &module_def, .Data);
                        var register: i32 = 0; // return values always go in the first set of registers, so index starts at 0
                        while (iter.next()) |input_node| {
                            try compile_data.register_map.put(input_node, @intCast(register));
                            std.debug.print("\t\tallocated slot {} (return) for node {}\n", .{ register, input_node });
                            register += 1;
                        }
                    } else {
                        var iter = node.edgesFilter(.In, &module_def, .Data);
                        while (iter.next()) |input_node| {
                            // for (input_nodes) |input_node| {
                            // if (input_node.isControl(module_def) == false) {
                            var register: u32 = 0;
                            if (input_node.type == .Instruction and input_node.opcode(module_def) == .Local_Get) {
                                const instruction = input_node.instruction(module_def);
                                register = instruction.immediate.Index;
                                std.debug.assert(register < register_slots.num_reserved); // ensure this register is actually reserved
                            } else {
                                register = try register_slots.alloc(input_node);
                            }
                            try compile_data.register_map.put(input_node, register);
                            std.debug.print("\t\tallocated slot {}\n", .{register});
                        }
                        // }
                    }
                }

                // add inputs to the FIFO visit queue
                for (input_nodes) |input_node| {
                    if (visited.contains(input_node) == false) {
                        std.debug.print("\t\tqueued up node {s}\n", .{input_node.prettyPrint(module_def)});
                        if (input_node.isControl(module_def)) {
                            try visit_stack_control_nodes.append(input_node);
                        } else {
                            try visit_queue.append(input_node);
                        }
                    }
                }
            }
        }

        // walk the graph in breadth-first order, starting from the stop node
        // reverse the instructions array when finished (alternatively just emit in reverse order if we have the node count from regalloc)

        std.debug.print("==== CODEGEN: emit instructions ====\n", .{});

        const instructions_begin = store.instructions.items.len;

        visit_stack_control_nodes.clearRetainingCapacity();
        visit_queue.clearRetainingCapacity();
        visited.clearRetainingCapacity();

        try visit_stack_control_nodes.append(func.stop);

        var instructions = &store.instructions;

        while (visit_queue.items.len > 0 or visit_stack_control_nodes.items.len > 0) {
            var node: *IRNode = undefined;
            if (visit_queue.items.len > 0) {
                node = visit_queue.orderedRemove(0); // visit the graph in breadth-first order (FIFO queue)

                // we could have marked this node as visited on an earlier pass since it could potentially be an
                // input into multiple nodes, or multiple inputs into the same node
                if (visited.contains(node)) {
                    continue;
                }

                std.debug.print("\tvisit data node {s} - {} outs, {} ins\n", .{ node.prettyPrint(module_def), node.edgesOut().len, node.edgesIn().len });
                // std.debug.assert(visited.contains(node) == false);
                std.debug.assert(node.isControl(module_def) == false);
            } else {
                node = visit_stack_control_nodes.pop();
                std.debug.print("\tvisit control node {s} - {} outs, {} ins\n", .{ node.prettyPrint(module_def), node.edgesOut().len, node.edgesIn().len });
                std.debug.assert(node.isControl(module_def));
                // std.debug.print("\tpopped control node {s}\n", .{node.prettyPrint(module_def)});
            }

            // std.debug.print("\tvisit node {s} - {} outs, {} ins\n", .{ node.prettyPrint(module_def), node.edgesOut().len, node.edgesIn().len });

            // only emit an instruction once all its out edges have been visited - this ensures all dependent instructions
            // will be executed after this one
            var did_visit_all_outputs: bool = true;
            for (node.edgesOut()) |output_node| {
                if (visited.contains(output_node) == false) {
                    did_visit_all_outputs = false;
                    std.debug.print("\tnot all outputs visited...\n", .{});
                    break;
                }
            }

            // TODO ideally dedupe the register slices to save cache space - since they don't change,
            // instructions can share their register slices if the values are the same. Could be as
            // simple as a hashmap([]u32, u32), where a slice hashes to an offset in the registers array.
            if (did_visit_all_outputs) {
                try visited.put(node, {});

                if (node.type == .Instruction) {
                    const instruction = node.instruction(module_def);
                    const opcode = instruction.opcode;
                    const immediates = instruction.immediate;

                    switch (opcode) {
                        .Local_Get => {
                            std.debug.print("\t\tskipped emit - flattened into register {}\n", .{node.instruction(module_def).immediate.Index});
                        },
                        else => {
                            const registers_begin = store.registers.items.len;
                            switch (opcode) {
                                .Local_Get => {
                                    // Local_Get doesn't have node inputs, it gets its input from its immediate index
                                    try store.registers.append(immediates.Index);
                                },
                                // .I32_Const => {
                                //     const input_register: ?u32 = compile_data.register_map.get(node);
                                //     std.debug.assert(input_register != null);
                                //     try store.registers.append(input_register.?);
                                // },
                                else => {
                                    for (node.edgesIn()) |input_node| {
                                        if (compile_data.register_map.get(input_node)) |input_register| {
                                            std.debug.print("\t\tinput node {s} for register {}\n", .{ input_node.prettyPrint(module_def), input_register });
                                            try store.registers.append(input_register);
                                        }
                                    }
                                },
                            }

                            if (compile_data.register_map.get(node)) |output_register| {
                                try store.registers.append(output_register);
                            }

                            const registers_end = store.registers.items.len;
                            const registers = store.registers.items[registers_begin..registers_end];

                            std.debug.print("\tregisters: {any}\n", .{registers});

                            try instructions.append(RegInstruction{
                                .opcode = node.opcode(module_def),
                                .immediate = immediates,
                                .registers = registers,
                            });
                        },
                    }
                }
            }
            // } else {
            //     // try again later
            //     if (node.type == .Instruction) {
            //         try visit_queue.append(node);
            //     }
            // }

            for (node.edgesIn()) |input_node| {
                std.debug.assert(input_node != node);

                if (visited.contains(input_node) == false) {
                    if (input_node.isControl(module_def)) {
                        try visit_stack_control_nodes.append(input_node);
                    } else {
                        try visit_queue.append(input_node);
                    }
                }
            }
        }

        const instructions_end = store.instructions.items.len;

        const emitted_instructions = store.instructions.items[instructions_begin..instructions_end];
        std.mem.reverse(RegInstruction, emitted_instructions);

        std.debug.print("==== CODEGEN: done (total instructions {}) ====\n\n", .{instructions_end - instructions_begin});

        try store.instances.append(FunctionInstance{
            .type_def_index = func.type_def_index,
            .def_index = func.def_index,
            .instructions_begin = instructions_begin,
            .num_params = num_params,
            .num_returns = num_returns,
            .num_locals = num_params + num_locals,
            .total_register_slots = register_slots.num_unique,
            // .instructions_end = instructions_end,
            // .local_types_begin = types_index_begin,
            // .local_types_end = types_index_end,
        });
    }

    fn dumpVizGraph(func: FunctionIR, path: []u8, module_def: ModuleDefinition, allocator: std.mem.Allocator) !void {
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
            const opcode: Opcode = n.opcode;
            const instruction = n.instruction(module_def);

            var label_buffer: [256]u8 = undefined;
            const label = switch (opcode) {
                .I32_Const => std.fmt.bufPrint(&label_buffer, ": {}", .{instruction.?.immediate.ValueI32}) catch unreachable,
                .I64_Const => std.fmt.bufPrint(&label_buffer, ": {}", .{instruction.?.immediate.ValueI64}) catch unreachable,
                .F32_Const => std.fmt.bufPrint(&label_buffer, ": {}", .{instruction.?.immediate.ValueF32}) catch unreachable,
                .F64_Const => std.fmt.bufPrint(&label_buffer, ": {}", .{instruction.?.immediate.ValueF64}) catch unreachable,
                .Call => std.fmt.bufPrint(&label_buffer, ": func {}", .{instruction.?.immediate.Index}) catch unreachable,
                .Local_Get, .Local_Set, .Local_Tee => std.fmt.bufPrint(&label_buffer, ": {}", .{instruction.?.immediate.Index}) catch unreachable,
                else => &[0]u8{},
            };

            var register_buffer: [64]u8 = undefined;
            const register = blk: {
                if (func.register_map.get(n)) |slot| {
                    break :blk std.fmt.bufPrint(&register_buffer, " @reg {}", .{slot}) catch unreachable;
                } else {
                    break :blk &[0]u8{};
                }
            };

            try writer.print("\"{*}\" [label=\"{}{s}{s}\"]\n", .{ n, opcode, label, register });

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

const IntermediateCompileData = struct {
    const UniqueValueToIRNodeMap = std.HashMap(TaggedVal, *IRNode, TaggedVal.HashMapContext, std.hash_map.default_max_load_percentage);

    const PendingContinuationEdge = struct {
        continuation: usize,
        node: *IRNode,
    };

    const BlockStack = struct {
        const Block = struct {
            node_start_index: u32,
            continuation: usize, // in instruction index space
            num_returns: u32,

            // records the state of stack and locals at the start of the block
            stack: std.ArrayList(*IRNode),
            locals: std.ArrayList(?*IRNode),

            fn init(start_index: u32, continuation: usize, num_returns: u32, allocator: std.mem.Allocator) Block {
                return Block{
                    .node_start_index = start_index,
                    .continuation = continuation,
                    .num_returns = num_returns,
                    .stack = std.ArrayList(*IRNode).init(allocator),
                    .locals = std.ArrayList(?*IRNode).init(allocator),
                };
            }

            fn initWithState(start_index: u32, continuation: usize, num_returns: u32, stack: []*IRNode, locals: []?*IRNode, allocator: std.mem.Allocator) AllocError!Block {
                var block = Block{
                    .node_start_index = start_index,
                    .continuation = continuation,
                    .num_returns = num_returns,
                    .stack = std.ArrayList(*IRNode).init(allocator),
                    .locals = std.ArrayList(?*IRNode).init(allocator),
                };
                try block.stack.appendSlice(stack);
                try block.locals.appendSlice(locals);

                return block;
            }

            fn deinit(self: Block) void {
                self.stack.deinit();
                self.locals.deinit();
            }
        };

        nodes: std.ArrayList(*IRNode),
        blocks: std.ArrayList(Block),
        allocator: std.mem.Allocator,

        // const ContinuationType = enum {
        //     .Normal,
        //     .Loop,
        // };

        fn init(allocator: std.mem.Allocator) BlockStack {
            return BlockStack{
                .nodes = std.ArrayList(*IRNode).init(allocator),
                .blocks = std.ArrayList(Block).init(allocator),
                .allocator = allocator,
            };
        }

        fn deinit(self: BlockStack) void {
            self.nodes.deinit();
            self.blocks.deinit();
        }

        fn push(self: *BlockStack, continuation: usize, num_returns: u32) AllocError!void {
            const block = Block.init(@intCast(self.nodes.items.len), continuation, num_returns, self.allocator);
            try self.blocks.append(block);
        }

        fn pushWithState(self: *BlockStack, continuation: usize, num_returns: u32, stack: []*IRNode, locals: []?*IRNode) AllocError!void {
            const block = try Block.initWithState(@intCast(self.nodes.items.len), continuation, num_returns, stack, locals, self.allocator);
            try self.blocks.append(block);
        }

        fn pushNode(self: *BlockStack, node: *IRNode) AllocError!void {
            try self.nodes.append(node);
        }

        fn popBlock(self: *BlockStack) Block {
            const block: Block = self.blocks.pop();

            std.debug.assert(block.node_start_index <= self.nodes.items.len);

            // should never grow these arrays
            std.debug.assert(block.node_start_index <= self.nodes.items.len);
            self.nodes.resize(block.node_start_index) catch unreachable;
            return block;
        }

        fn currentBlockNodes(self: *BlockStack) []*IRNode {
            // std.debug.print(">>>>>>>> num block: {}\n", .{self.blocks.items.len});
            const index: u32 = self.blocks.items[self.blocks.items.len - 1].node_start_index;
            return self.nodes.items[index..];
        }

        fn reset(self: *BlockStack) void {
            self.nodes.clearRetainingCapacity();
            self.blocks.clearRetainingCapacity();
        }
    };

    allocator: std.mem.Allocator,

    // all_nodes: std.ArrayList(*IRNode),

    blocks: BlockStack,

    // This stack is a record of the nodes to push values onto the stack. If an instruction would push
    // multiple values onto the stack, it would be in this list as many times as values it pushed. Note
    // that we don't have to do any type checking here because the module has already been validated.
    value_stack: std.ArrayList(*IRNode),

    // records the current block continuation
    // label_continuations: std.ArrayList(u32),

    pending_continuation_edges: std.ArrayList(PendingContinuationEdge),

    // when hitting an unconditional control transfer, we need to mark the rest of the stack values as unreachable just like in validation
    is_unreachable: bool,

    // This is a bit weird - since the Local_* instructions serve to just manipulate the locals into the stack,
    // we need a way to represent what's in the locals slot as an SSA node. This array lets us do that. We also
    // reuse the Local_Get instructions to indicate the "initial value" of the slot. Since our IRNode only stores
    // indices to instructions, we'll just lazily set these when they're fetched for the first time.
    locals: std.ArrayList(?*IRNode),

    // Lets us collapse multiple const IR nodes with the same type/value into a single one
    unique_constants: UniqueValueToIRNodeMap,

    //
    register_map: std.AutoHashMap(*const IRNode, u32),

    scratch_node_list_1: std.ArrayList(*IRNode),
    scratch_node_list_2: std.ArrayList(*IRNode),

    fn init(allocator: std.mem.Allocator) IntermediateCompileData {
        return IntermediateCompileData{
            .allocator = allocator,
            // .all_nodes = std.ArrayList(*IRNode).init(allocator),
            .blocks = BlockStack.init(allocator),
            .value_stack = std.ArrayList(*IRNode).init(allocator),
            // .label_continuations = std.ArrayList(u32).init(allocator),
            .pending_continuation_edges = std.ArrayList(PendingContinuationEdge).init(allocator),
            .is_unreachable = false,
            .locals = std.ArrayList(?*IRNode).init(allocator),
            .unique_constants = UniqueValueToIRNodeMap.init(allocator),
            .register_map = std.AutoHashMap(*const IRNode, u32).init(allocator),
            .scratch_node_list_1 = std.ArrayList(*IRNode).init(allocator),
            .scratch_node_list_2 = std.ArrayList(*IRNode).init(allocator),
        };
    }

    fn warmup(self: *IntermediateCompileData, func_def: FunctionDefinition, module_def: ModuleDefinition) AllocError!void {
        try self.locals.appendNTimes(null, func_def.numParamsAndLocals(module_def));
        try self.scratch_node_list_1.ensureTotalCapacity(4096);
        try self.scratch_node_list_2.ensureTotalCapacity(4096);
        try self.register_map.ensureTotalCapacity(1024);
        // try self.label_continuations.append(func_def.continuation);
        self.is_unreachable = false;
    }

    fn reset(self: *IntermediateCompileData) void {
        // self.all_nodes.clearRetainingCapacity();
        self.blocks.reset();
        self.value_stack.clearRetainingCapacity();
        // self.label_continuations.clearRetainingCapacity();
        self.pending_continuation_edges.clearRetainingCapacity();
        self.locals.clearRetainingCapacity();
        self.unique_constants.clearRetainingCapacity();
        self.register_map.clearRetainingCapacity();
        self.scratch_node_list_1.clearRetainingCapacity();
        self.scratch_node_list_2.clearRetainingCapacity();
    }

    fn deinit(self: *IntermediateCompileData) void {
        // self.all_nodes.deinit();
        self.blocks.deinit();
        self.value_stack.deinit();
        // self.label_continuations.deinit();
        self.pending_continuation_edges.deinit();
        self.locals.deinit();
        self.unique_constants.deinit();
        self.register_map.deinit();
        self.scratch_node_list_1.deinit();
        self.scratch_node_list_2.deinit();
    }

    fn popPushValueStackNodes(self: *IntermediateCompileData, node: *IRNode, num_consumed: usize, num_pushed: usize, module_def: ModuleDefinition) AllocError!void {
        if (self.is_unreachable) {
            return;
        }

        if (num_consumed > 0) {
            var edges_buffer: [8]*IRNode = undefined; // 8 should be more stack slots than any one instruction can pop
            std.debug.assert(num_consumed <= edges_buffer.len);

            const edges = edges_buffer[0..num_consumed];
            for (edges) |*e| {
                e.* = self.value_stack.pop();
            }
            try node.pushEdges(.In, edges, module_def, self.allocator);
            for (edges) |e| {
                try e.pushEdge(.Out, node, module_def, self.allocator);
            }
        }

        try self.value_stack.appendNTimes(node, num_pushed);
    }

    // TODO: could have a limit on how many constants can be folded at a particular time. And when the limit is run over, have some
    // sort of LRU cache scheme that evicts the oldest constant. This way pathologically bad functions that have an insane number
    // of constants don't inflate permanent register usage too much.
    fn foldConstant(self: *IntermediateCompileData, compiler: *FunctionCompiler, comptime valtype: ValType, instruction_index: u32, instruction: Instruction) AllocError!*IRNode {
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

        const res = try self.unique_constants.getOrPut(val);
        if (res.found_existing == false) {
            const node = try IRNode.createInstruction(instruction_index, compiler);
            res.value_ptr.* = node;
        }
        if (self.is_unreachable == false) {
            try self.value_stack.append(res.value_ptr.*);
        }
        return res.value_ptr.*;
    }

    fn addPendingEdgeLabel(self: *IntermediateCompileData, node: *IRNode, label_id: u32) !void {
        const last_block_index = self.blocks.blocks.items.len - 1;
        const continuation: usize = self.blocks.blocks.items[last_block_index - label_id].continuation;
        try self.pending_continuation_edges.append(PendingContinuationEdge{
            .node = node,
            .continuation = continuation,
        });
    }

    fn addPendingEdgeContinuation(self: *IntermediateCompileData, node: *IRNode, continuation: u32) !void {
        try self.pending_continuation_edges.append(PendingContinuationEdge{
            .node = node,
            .continuation = continuation,
        });
    }
};

// register instructions get a slice of the overall set of register slots, which are pointers to actual
// registers (?)

const RegInstruction = struct {
    opcode: Opcode,
    immediate: def.InstructionImmediates,
    registers: []u32,

    // fn numRegisters(self: RegInstruction) u4 {
    //     switch (self.opcode) {}
    // }

    // fn registers(self: RegInstruction, register_slice: []Val) []Val {
    //     return register_slice[self.registerOffset .. self.registerOffset + self.numRegisters()];
    // }
};

const FunctionCompiler = struct {
    allocator: std.mem.Allocator,
    module_def: *const ModuleDefinition,
    ir: StableArray(IRNode),

    fn init(allocator: std.mem.Allocator, module_def: *const ModuleDefinition) FunctionCompiler {
        return FunctionCompiler{
            .allocator = allocator,
            .module_def = module_def,
            .ir = StableArray(IRNode).init(1024 * 1024 * 8),
        };
    }

    fn deinit(compiler: *FunctionCompiler) void {
        for (compiler.ir.items) |node| {
            node.deinit(compiler.allocator);
        }
        compiler.ir.deinit();
    }

    fn compile(compiler: *FunctionCompiler, store: *FunctionStore) AllocError!void {
        var compile_data = IntermediateCompileData.init(compiler.allocator);
        defer compile_data.deinit();

        for (0..compiler.module_def.functions.items.len) |i| {
            // std.debug.print("compiler.module_def.functions.items.len: {}, i: {}\n\n", .{ compiler.module_def.functions.items.len, i });
            if (try compiler.generateIR(i, &compile_data)) |function_ir| {
                try function_ir.codegen(store, &compile_data, compiler.module_def.*, compiler.allocator);
            }

            compile_data.reset();
        }
    }

    fn generateIR(compiler: *FunctionCompiler, index: usize, compile_data: *IntermediateCompileData) AllocError!?FunctionIR {
        const UniqueValueToIRNodeMap = std.HashMap(TaggedVal, *IRNode, TaggedVal.HashMapContext, std.hash_map.default_max_load_percentage);

        const Helpers = struct {
            fn opcodeHasDefaultIRMapping(opcode: Opcode) bool {
                return switch (opcode) {
                    .Noop,
                    .Block,
                    .Loop,
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

        const module_def: *const ModuleDefinition = compiler.module_def;
        const func: *const FunctionDefinition = &module_def.functions.items[index];
        const func_type: *const FunctionTypeDefinition = func.typeDefinition(module_def.*);

        std.debug.print("compiling func index {}\n", .{index});

        try compile_data.warmup(func.*, module_def.*);

        try compile_data.blocks.push(func.continuation, func_type.calcNumReturns());

        var locals = compile_data.locals.items; // for convenience later

        // Lets us collapse multiple const IR nodes with the same type/value into a single one
        var unique_constants = UniqueValueToIRNodeMap.init(compiler.allocator);
        defer unique_constants.deinit();

        const instructions: []Instruction = func.instructions(module_def.*);
        if (instructions.len == 0) {
            std.log.warn("Skipping function with no instructions (index {}).", .{index});
            return null;
        }

        const start: *IRNode = try IRNode.create(.Start, compiler);
        const stop: *IRNode = try IRNode.create(.Stop, compiler);
        var current_control_node: *IRNode = start;

        // mainly for If instructions to help the corresponding End instruction figure out if they should swap the block stack/locals
        var instruction_control_stack = std.ArrayList(*IRNode).init(compiler.allocator);
        defer instruction_control_stack.deinit();

        for (instructions, 0..) |instruction, local_instruction_index| {
            const instruction_index: u32 = @intCast(func.instructions_begin + local_instruction_index);

            var node: ?*IRNode = null;
            if (Helpers.opcodeHasDefaultIRMapping(instruction.opcode)) {
                node = try IRNode.createInstruction(instruction_index, compiler);
            }

            std.debug.print("opcode: {}\n", .{instruction.opcode});

            switch (instruction.opcode) {
                .Block => {
                    // compile_data.label_stack += 1;

                    // try compile_data.label_stack.append(node);
                    // try compile_data.label_continuations.append(instruction.immediate.Block.continuation);

                    // instruction.immediate.Block
                    const block_immediates = instruction.immediate.Block;
                    const num_block_returns = BlockTypeValue.getBlocktypeReturnTypes(block_immediates.block_value, block_immediates.block_type, module_def).len;

                    try compile_data.blocks.push(instruction.immediate.Block.continuation, @intCast(num_block_returns));
                },
                // .Loop => {
                //     // compile_data.label_stack += 1;
                //     // compile_data.label_stack.append(node);
                //     // try compile_data.label_continuations.append(instruction.immediate.Block.continuation);
                //     try compile_data.blocks.push(instruction.immediate.Block.continuation); // TODO record the kind of block so we know this is a loop?
                // },
                .If => {
                    try current_control_node.pushEdge(.Out, node.?, module_def.*, compiler.allocator);
                    try node.?.pushEdge(.In, current_control_node, module_def.*, compiler.allocator);
                    current_control_node = node.?;

                    try instruction_control_stack.append(node.?);

                    // var phi_nodes: *std.ArrayList(*IRNode) = &compile_data.scratch_node_list_1;
                    // defer compile_data.scratch_node_list_1.clearRetainingCapacity();

                    // std.debug.assert(phi_nodes.items.len == 0);

                    // for (0..instruction.immediate.If.num_returns) |_| {
                    //     const phi: *IRNode = try IRNode.create(.Phi, compiler);
                    //     try phi_nodes.append(phi);
                    // }

                    // make sure the if node consumes the top stack value before making a copy of it when the block is pushed
                    try compile_data.popPushValueStackNodes(node.?, 1, 0, module_def.*);

                    try compile_data.blocks.pushWithState(instruction.immediate.If.end_continuation, instruction.immediate.If.num_returns, compile_data.value_stack.items, compile_data.locals.items);
                    // try compile_data.addPendingEdgeContinuation(node.?, instruction.immediate.If.end_continuation + 1);
                    // try compile_data.addPendingEdgeContinuation(node.?, instruction.immediate.If.else_continuation);

                    // after the if consumes the value it needs, push the phi nodes on since these will be the return values
                    // of the block
                    // try compile_data.value_stack.appendSlice(phi_nodes.items);
                },
                .IfNoElse => {
                    std.debug.assert(instruction.immediate.If.num_returns == 0);

                    try current_control_node.pushEdge(.Out, node.?, module_def.*, compiler.allocator);
                    try node.?.pushEdge(.In, current_control_node, module_def.*, compiler.allocator);
                    current_control_node = node.?;

                    try instruction_control_stack.append(node.?);

                    // make sure the if node consumes the top stack value before making a copy of it when the block is pushed
                    try compile_data.popPushValueStackNodes(node.?, 1, 0, module_def.*);

                    try compile_data.blocks.pushWithState(instruction.immediate.If.end_continuation, 0, compile_data.value_stack.items, compile_data.locals.items);
                    // try compile_data.addPendingEdgeContinuation(node.?, instruction.immediate.If.end_continuation + 1);
                    // try compile_data.addPendingEdgeContinuation(node.?, instruction.immediate.If.else_continuation);
                },
                .Else => {
                    // try compile_data.addPendingEdgeContinuation(node.?, instruction.immediate.If.end_continuation + 1);

                    const block: *IntermediateCompileData.BlockStack.Block = &compile_data.blocks.blocks.items[compile_data.blocks.blocks.items.len - 1];
                    std.mem.swap(std.ArrayList(*IRNode), &block.stack, &compile_data.value_stack);
                    std.mem.swap(std.ArrayList(?*IRNode), &block.locals, &compile_data.locals);
                },
                .End => {
                    var block: IntermediateCompileData.BlockStack.Block = compile_data.blocks.popBlock();
                    defer block.deinit();

                    // resolve the current stack and locals with the saved state via phi nodes. only If/IfNoElse should fall into here
                    if (block.stack.items.len > 0 or block.locals.items.len > 0) {
                        const region: *IRNode = try IRNode.create(.Region, compiler);
                        try region.pushEdge(.In, current_control_node, module_def.*, compiler.allocator);
                        try current_control_node.pushEdge(.Out, region, module_def.*, compiler.allocator);

                        current_control_node = region;

                        var phi_nodes: *std.ArrayList(*IRNode) = &compile_data.scratch_node_list_1;
                        std.debug.assert(phi_nodes.items.len == 0);
                        defer phi_nodes.clearRetainingCapacity();

                        // Ensure the stack and local nodes are the ones from the truthy branch, so the stack
                        // comparison code can push the edges in the correct order
                        const block_pair_node = instruction_control_stack.pop();
                        const block_pair_opcode = block_pair_node.opcode(module_def.*);
                        std.debug.assert(block_pair_opcode == .If or block_pair_opcode == .IfNoElse);
                        if (block_pair_opcode == .If) {
                            std.mem.swap(std.ArrayList(*IRNode), &block.stack, &compile_data.value_stack);
                            std.mem.swap(std.ArrayList(?*IRNode), &block.locals, &compile_data.locals);
                        }

                        // TODO figure out if we can optimize these compares by only looking at values that actually changed

                        if (block.stack.items.len > 0) {
                            std.debug.assert(block.stack.items.len == compile_data.value_stack.items.len);
                            for (block.stack.items, compile_data.value_stack.items, 0..) |false_value, true_value, i| {
                                if (false_value != true_value) {
                                    const phi: *IRNode = try IRNode.create(.Phi, compiler);
                                    const in_edges = [_]*IRNode{ true_value, false_value }; // TODO maybe need that Proj node to make sure these are coming from the correct if/else branch?
                                    try phi.pushEdges(.In, &in_edges, module_def.*, compiler.allocator);
                                    try phi.pushEdge(.Out, region, module_def.*, compiler.allocator);

                                    compile_data.value_stack.items[i] = phi; // TODO I wonder if aliasing is a problem here

                                    try phi_nodes.append(phi);
                                }
                            }
                        }

                        if (block.locals.items.len > 0) {
                            std.debug.assert(block.locals.items.len == compile_data.locals.items.len);

                            // don't need to compare parameters since they are immutable
                            const num_params = func_type.num_params;
                            for (block.locals.items[num_params..], compile_data.locals.items[num_params..], num_params..) |false_local, true_local, i| {
                                std.debug.print("\ttrue_local: {?}\n", .{true_local});
                                std.debug.print("\tfalse_local: {?}\n", .{false_local});
                                if (false_local != true_local) {
                                    std.debug.assert(true_local != null);
                                    std.debug.assert(false_local != null);

                                    const phi: *IRNode = try IRNode.create(.Phi, compiler);
                                    const in_edges = [_]*IRNode{ true_local.?, false_local.? }; // TODO maybe need that Proj node to make sure these are coming from the correct if/else branch?
                                    try phi.pushEdges(.In, &in_edges, module_def.*, compiler.allocator);
                                    try phi.pushEdge(.Out, region, module_def.*, compiler.allocator);

                                    compile_data.locals.items[i] = phi; // TODO I wonder if aliasing is a problem here

                                    try phi_nodes.append(phi);
                                }
                            }
                        }

                        if (phi_nodes.items.len > 0) {
                            try region.pushEdges(.In, phi_nodes.items, module_def.*, compiler.allocator); // note that phis don't have a back edge to the control region (at least right now...)
                        }
                    } else {
                        std.debug.assert(block.stack.items.len == 0);
                        std.debug.assert(block.locals.items.len == 0);

                        const out_edges = [_]*IRNode{node.?};
                        try current_control_node.pushEdges(.Out, &out_edges, module_def.*, compiler.allocator);

                        const in_edges = [_]*IRNode{current_control_node};
                        try node.?.pushEdges(.In, &in_edges, module_def.*, compiler.allocator);

                        current_control_node = node.?;
                    }

                    // the last End opcode returns the values on the stack
                    if (compile_data.blocks.blocks.items.len == 0) {
                        // node = try IRNode.createStandalone(compiler, .Return);
                        try compile_data.popPushValueStackNodes(node.?, func_type.getReturns().len, 0, module_def.*);
                        // _ = compile_data.label_continuations.pop();
                    }

                    // At the end of every block, we ensure all nodes with side effects are still in the graph. Order matters
                    // since mutations to the Store or control flow changes must happen in the order of the original instructions.
                    // {
                    //     var nodes_with_side_effects: *std.ArrayList(*IRNode) = &compile_data.scratch_node_list_1;
                    //     defer nodes_with_side_effects.clearRetainingCapacity();

                    //     const current_block_nodes: []*IRNode = compile_data.blocks.currentBlockNodes();

                    //     for (current_block_nodes) |block_node| {
                    //         if (block_node.hasSideEffects() or block_node.isControl()) {
                    //             try nodes_with_side_effects.append(block_node);
                    //         }
                    //     }

                    //     if (nodes_with_side_effects.items.len >= 2) {
                    //         var i: i32 = @intCast(nodes_with_side_effects.items.len - 2);
                    //         while (i >= 0) : (i -= 1) {
                    //             const ii: u32 = @intCast(i);
                    //             var node_a: *IRNode = nodes_with_side_effects.items[ii];
                    //             if (try node_a.isIsland(&compile_data.scratch_node_list_2)) {
                    //                 var node_b: *IRNode = nodes_with_side_effects.items[ii + 1];

                    //                 var in_edges = [_]*IRNode{node_b};
                    //                 try node_a.pushEdges(.Out, &in_edges, compile_data.allocator);

                    //                 var out_edges = [_]*IRNode{node_a};
                    //                 try node_b.pushEdges(.In, &out_edges, compile_data.allocator);
                    //             }
                    //         }
                    //     }
                    // }
                },
                .Branch => {
                    try compile_data.addPendingEdgeLabel(node.?, instruction.immediate.LabelId);
                    compile_data.is_unreachable = true;
                },
                .Branch_If => {
                    try compile_data.popPushValueStackNodes(node.?, 1, 0, module_def.*);
                },
                .Branch_Table => {
                    assert(node != null);

                    try compile_data.popPushValueStackNodes(node.?, 1, 0, module_def.*);

                    // var continuation_edges: std.ArrayList(*IRNode).init(allocator);
                    // defer continuation_edges.deinit();

                    const immediates: *const BranchTableImmediates = &module_def.code.branch_table.items[instruction.immediate.Index];

                    try compile_data.addPendingEdgeLabel(node.?, immediates.fallback_id);
                    const label_ids: []const u32 = immediates.getLabelIds(module_def.*);
                    for (label_ids) |continuation| {
                        try compile_data.addPendingEdgeLabel(node.?, continuation);
                    }

                    compile_data.is_unreachable = true;

                    // try label_ids.append(immediates.fallback_id);
                    // try label_ids.appendSlice(immediates.label_ids.items);

                    // node.pushEdges(.Out, )
                    // TODO need to somehow connect to the various labels it wants to jump to?
                },
                .Return => {
                    try compile_data.popPushValueStackNodes(node.?, func_type.getReturns().len, 0, module_def.*);
                    compile_data.is_unreachable = true;
                },
                .Call => {
                    const call_index = instruction.immediate.Index;
                    const type_index = blk: {
                        if (index < module_def.imports.functions.items.len) {
                            const import: *const FunctionImportDefinition = &module_def.imports.functions.items[call_index];
                            break :blk import.type_index;
                        } else {
                            const local_index = module_def.imports.functions.items.len - call_index;
                            const call_def: *const FunctionDefinition = &module_def.functions.items[local_index];
                            break :blk call_def.type_index;
                        }
                    };
                    const calling_func_type: *const FunctionTypeDefinition = &module_def.types.items[type_index];
                    const num_params: usize = calling_func_type.num_params;
                    const num_returns: usize = calling_func_type.calcNumReturns();

                    try compile_data.popPushValueStackNodes(node.?, num_params, num_returns, module_def.*);
                },
                // .Call_Indirect
                .Drop => {
                    if (compile_data.is_unreachable == false) {
                        _ = compile_data.value_stack.pop();
                    }
                },
                .Select, .Select_T => {
                    try compile_data.popPushValueStackNodes(node.?, 3, 1, module_def.*);
                },
                .I32_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(compiler, .I32, instruction_index, instruction);
                },
                .I64_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(compiler, .I64, instruction_index, instruction);
                },
                .F32_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(compiler, .F32, instruction_index, instruction);
                },
                .F64_Const => {
                    assert(node == null);
                    node = try compile_data.foldConstant(compiler, .F64, instruction_index, instruction);
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
                .I64_Eq,
                .I64_NE,
                .I64_LT_S,
                .I64_LT_U,
                .I64_GT_S,
                .I64_GT_U,
                .I64_LE_S,
                .I64_LE_U,
                .I64_GE_S,
                .I64_GE_U,
                .I64_Add,
                .I64_Sub,
                .I64_Mul,
                .I64_Div_S,
                .I64_Div_U,
                .I64_Rem_S,
                .I64_Rem_U,
                .I64_And,
                .I64_Or,
                .I64_Xor,
                .I64_Shl,
                .I64_Shr_S,
                .I64_Shr_U,
                .I64_Rotl,
                .I64_Rotr,

                // TODO add a lot more of these simpler opcodes
                => {
                    try compile_data.popPushValueStackNodes(node.?, 2, 1, module_def.*);
                },
                .I32_Eqz,
                .I32_Clz,
                .I32_Ctz,
                .I32_Popcnt,
                .I32_Extend8_S,
                .I32_Extend16_S,
                .I64_Eqz,
                .I64_Clz,
                .I64_Ctz,
                .I64_Popcnt,
                .I64_Extend8_S,
                .I64_Extend16_S,
                .I64_Extend32_S,
                .F32_Neg,
                .F64_Neg,
                => {
                    try compile_data.popPushValueStackNodes(node.?, 1, 1, module_def.*);
                },
                .Local_Get => {
                    assert(node == null);

                    if (compile_data.is_unreachable == false) {
                        const local: *?*IRNode = &locals[instruction.immediate.Index];
                        if (local.* == null) {
                            local.* = try IRNode.createInstruction(instruction_index, compiler);
                        }
                        node = local.*;
                        try compile_data.value_stack.append(node.?);
                    }
                },
                .Local_Set => {
                    assert(node == null);

                    if (compile_data.is_unreachable == false) {
                        const n: *IRNode = compile_data.value_stack.pop();
                        locals[instruction.immediate.Index] = n;
                    }
                },
                .Local_Tee => {
                    assert(node == null);
                    if (compile_data.is_unreachable == false) {
                        const n: *IRNode = compile_data.value_stack.items[compile_data.value_stack.items.len - 1];
                        locals[instruction.immediate.Index] = n;
                    }
                },
                else => {
                    std.log.err("skipping node {}", .{instruction.opcode});
                    unreachable;
                },
            }

            // resolve any pending continuations with the current node.
            if (node) |current_node| {
                var i: usize = 0;
                while (i < compile_data.pending_continuation_edges.items.len) {
                    var pending: *IntermediateCompileData.PendingContinuationEdge = &compile_data.pending_continuation_edges.items[i];

                    if (pending.continuation == instruction_index) {
                        var out_edges = [_]*IRNode{current_node};
                        try pending.node.pushEdges(.Out, &out_edges, module_def.*, compile_data.allocator);

                        var in_edges = [_]*IRNode{pending.node};
                        try current_node.pushEdges(.In, &in_edges, module_def.*, compile_data.allocator);

                        _ = compile_data.pending_continuation_edges.swapRemove(i);
                    } else {
                        i += 1;
                    }
                }

                // try compile_data.all_nodes.append(current_node);

                try compile_data.blocks.pushNode(current_node);
            }
        }

        try current_control_node.pushEdges(.Out, &[_]*IRNode{stop}, module_def.*, compiler.allocator);
        try stop.pushEdges(.In, &[_]*IRNode{current_control_node}, module_def.*, compiler.allocator);

        // resolve any nodes that have side effects that somehow became isolated
        // TODO will have to stress test this with a bunch of different cases of nodes
        // for (compile_data.all_nodes.items[0 .. compile_data.all_nodes.items.len - 1]) |node| {
        //     if (node.hasSideEffects()) {
        //         if (try node.isIsland(&compile_data.scratch_node_list_1)) {
        //             var last_node: *IRNode = compile_data.all_nodes.items[compile_data.all_nodes.items.len - 1];

        //             var out_edges = [_]*IRNode{last_node};
        //             try node.pushEdges(.Out, &out_edges, compile_data.allocator);

        //             var in_edges = [_]*IRNode{node};
        //             try last_node.pushEdges(.In, &in_edges, compile_data.allocator);
        //         }
        //     }
        // }

        return FunctionIR{
            .def_index = index,
            .type_def_index = func.type_index,
            .start = start,
            .stop = stop,
        };
    }
};

const FunctionInstance = struct {
    type_def_index: usize,
    def_index: usize,
    instructions_begin: usize,
    num_locals: u32,
    num_params: u32,
    num_returns: u32,
    total_register_slots: u32,
    // instructions_end: usize,
    // local_types_begin: usize,
    // local_types_end: usize,

    fn instructions(func: FunctionInstance, store: FunctionStore) []RegInstruction {
        return store.instructions.items[func.instructions_begin..func.instructions_end];
    }

    fn localTypes(func: FunctionInstance, store: FunctionStore) []ValType {
        return store.local_types.items[func.local_types_begin..func.local_types_end];
    }

    fn typeDefinition(func: FunctionInstance, module_def: ModuleDefinition) *const FunctionTypeDefinition {
        return &module_def.types.items[func.type_def_index];
    }

    fn definition(func: FunctionInstance, module_def: ModuleDefinition) *const FunctionDefinition {
        return &module_def.functions.items[func.def_index];
    }
};

const Label = struct {
    continuation: u32,
    // num_returns: u32,
    // registers_begin: u32,
};

const CallFrame = struct {
    func: *const FunctionInstance,
    module_instance: *ModuleInstance,
    num_returns: u32,
    registers_begin: u32,
    labels_begin: u32,
};

const MachineState = struct {
    const AllocOpts = struct {
        max_registers: usize,
        max_labels: usize,
        max_frames: usize,
    };

    registers: []Val,
    labels: []Label,
    frames: []CallFrame,
    num_registers: u32,
    num_labels: u16,
    num_frames: u16,
    mem: []u8,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) MachineState {
        return MachineState{
            .registers = &[_]Val{},
            .labels = &[_]Label{},
            .frames = &[_]CallFrame{},
            .num_registers = 0,
            .num_labels = 0,
            .num_frames = 0,
            .mem = &[_]u8{},
            .allocator = allocator,
        };
    }

    fn deinit(ms: *MachineState) void {
        if (ms.mem.len > 0) {
            ms.allocator.free(ms.mem);
        }
    }

    fn allocMemory(ms: *MachineState, opts: AllocOpts) AllocError!void {
        const alignment = @max(@alignOf(Val), @alignOf(Label), @alignOf(CallFrame));
        const values_alloc_size = std.mem.alignForward(usize, @as(usize, @intCast(opts.max_registers)) * @sizeOf(Val), alignment);
        const labels_alloc_size = std.mem.alignForward(usize, @as(usize, @intCast(opts.max_labels)) * @sizeOf(Label), alignment);
        const frames_alloc_size = std.mem.alignForward(usize, @as(usize, @intCast(opts.max_frames)) * @sizeOf(CallFrame), alignment);
        const total_alloc_size: usize = values_alloc_size + labels_alloc_size + frames_alloc_size;

        const begin_labels = values_alloc_size;
        const begin_frames = values_alloc_size + labels_alloc_size;

        ms.mem = try ms.allocator.alloc(u8, total_alloc_size);
        ms.registers.ptr = @as([*]Val, @alignCast(@ptrCast(ms.mem.ptr)));
        ms.registers.len = opts.max_registers;
        ms.labels.ptr = @as([*]Label, @alignCast(@ptrCast(ms.mem[begin_labels..].ptr)));
        ms.labels.len = opts.max_labels;
        ms.frames.ptr = @as([*]CallFrame, @alignCast(@ptrCast(ms.mem[begin_frames..].ptr)));
        ms.frames.len = opts.max_frames;
    }

    fn checkExhausted(ms: MachineState, extra_registers: u32) TrapError!void {
        if (ms.num_registers + extra_registers >= ms.registers.len) {
            return error.TrapStackExhausted;
        }
    }

    fn reset(ms: *MachineState) void {
        ms.num_registers = 0;
        ms.num_labels = 0;
        ms.num_frames = 0;
    }

    fn getVal(ms: MachineState, register: u32) Val {
        const frame: *CallFrame = ms.topFrame();
        const slot = frame.registers_begin + register;
        return ms.registers[slot];
    }

    fn getType(ms: MachineState, comptime T: type, register: u32) T {
        return switch (T) {
            i32 => ms.getI32(register),
            i64 => ms.getI64(register),
            f32 => ms.getF32(register),
            f64 => ms.getF64(register),
            else => unreachable,
        };
    }

    fn getI32(ms: MachineState, register: u32) i32 {
        return ms.getVal(register).I32;
    }

    fn getI64(ms: MachineState, register: u32) i64 {
        return ms.getVal(register).I64;
    }

    fn getF32(ms: MachineState, register: u32) f32 {
        return ms.getVal(register).F32;
    }

    fn getF64(ms: MachineState, register: u32) f64 {
        return ms.getVal(register).F64;
    }

    fn setVal(ms: *MachineState, register: u32, val: Val) void {
        const frame: *CallFrame = ms.topFrame();
        const slot = frame.registers_begin + register;
        ms.registers[slot] = val;
    }

    fn setType(ms: *MachineState, comptime T: type, register: u32, val: T) void {
        switch (T) {
            i32 => ms.setI32(register, val),
            i64 => ms.setI64(register, val),
            f32 => ms.setF32(register, val),
            f64 => ms.setF64(register, val),
            else => unreachable,
        }
    }

    fn setI32(ms: *MachineState, register: u32, val: i32) void {
        const frame: *CallFrame = ms.topFrame();
        const slot = frame.registers_begin + register;
        ms.registers[slot].I32 = val;
    }

    fn setI64(ms: *MachineState, register: u32, val: i64) void {
        const frame: *CallFrame = ms.topFrame();
        const slot = frame.registers_begin + register;
        ms.registers[slot].I64 = val;
    }

    fn setF32(ms: *MachineState, register: u32, val: f32) void {
        const frame: *CallFrame = ms.topFrame();
        const slot = frame.registers_begin + register;
        ms.registers[slot].F32 = val;
    }

    fn setF64(ms: *MachineState, register: u32, val: f64) void {
        const frame: *CallFrame = ms.topFrame();
        const slot = frame.registers_begin + register;
        ms.registers[slot].F64 = val;
    }

    fn topFrame(ms: MachineState) *CallFrame {
        return &ms.frames[ms.num_frames - 1];
    }

    fn pushFrame(ms: *MachineState, func: FunctionInstance, module_instance: *ModuleInstance) TrapError!void {
        if (ms.num_frames + 1 < ms.frames.len) {
            ms.frames[ms.num_frames] = CallFrame{
                .func = &func,
                .module_instance = module_instance,
                .num_returns = func.num_returns,
                .registers_begin = ms.num_registers,
                .labels_begin = ms.num_labels,
            };
            ms.num_frames += 1;
            ms.num_registers += func.total_register_slots;
        } else {
            return TrapError.TrapStackExhausted;
        }
    }

    fn popFrame(ms: *MachineState) void {
        const frame: *CallFrame = ms.topFrame();
        ms.num_registers = frame.registers_begin;
        ms.num_labels = frame.labels_begin;
        ms.num_frames -= 1;

        // TODO return continuation data
    }

    fn pushLabel(ms: *MachineState, num_returns: u32, continuation: u32) TrapError!void {
        _ = num_returns;

        if (ms.num_labels < ms.labels.len) {
            ms.labels[ms.num_labels] = Label{
                // .num_returns = num_returns,
                .continuation = continuation,
                // .start_offset_values = ms.num_values,
            };
            ms.num_labels += 1;
        } else {
            return TrapError.TrapStackExhausted;
        }
    }

    fn popLabel(ms: *MachineState) void {
        ms.num_labels -= 1;
    }

    fn findLabel(ms: MachineState, id: u32) *const Label {
        const index: usize = (ms.num_labels - 1) - id;
        return &ms.labels[index];
    }

    fn topLabel(ms: MachineState) *const Label {
        return &ms.labels[ms.num_labels - 1];
    }

    fn frameLabel(ms: MachineState) *const Label {
        const frame: *const CallFrame = ms.topFrame();
        const frame_label: *const Label = &ms.labels[frame.start_offset_labels];
        return frame_label;
    }

    fn traceInstruction(state: MachineState, instruction_name: []const u8, pc: u32) void {
        if (config.enable_debug_trace and DebugTrace.shouldTraceInstructions()) {
            const frame: *const CallFrame = state.topFrame();
            const name_section: *const NameCustomSection = &frame.module_instance.module_def.name_section;
            const module_name = name_section.getModuleName();
            const function_name = name_section.findFunctionName(frame.func.def_index);

            std.debug.print("\t0x{x} - {s}!{s}: {s}\n", .{ pc, module_name, function_name, instruction_name });
        }
    }
};

// pc is the "program counter", which points to the next instruction to execute
const InstructionFunc = *const fn (pc: u32, code: [*]const RegInstruction, state: *MachineState) TrapError!void;

// Maps all instructions to an execution function, to map opcodes directly to function pointers
// which avoids a giant switch statement. Because the switch-style has a single conditional
// branch for every opcode, the branch predictor cannot reliably predict the next opcode. However,
// giving each instruction its own branch allows the branch predictor to cache heuristics for each
// instruction, instead of a single branch. This approach is combined with tail calls to ensure the
// stack doesn't overflow and help optimize the generated asm.
// In the past, this style of opcode dispatch has been called the poorly-named "threaded code" approach.
// See the "continuation-passing style" section of this article:
// http://www.complang.tuwien.ac.at/forth/threaded-code.html
const InstructionFuncs = struct {
    comptime {
        std.debug.assert(opcodeToFuncTable.len == @typeInfo(Opcode).Enum.fields.len);
    }

    const opcodeToFuncTable = [_]InstructionFunc{
        &op_Invalid,
        &op_Unreachable,
        &op_Noop, // &op_DebugTrap,
        &op_Noop,
        &op_Noop, // &op_Block,
        &op_Noop, // &op_Loop,
        &op_Noop, // &op_If,
        &op_Noop, // &op_IfNoElse,
        &op_Noop, // &op_Else,
        &op_End, // &op_End,
        &op_Noop, // &op_Branch,
        &op_Noop, // &op_Branch_If,
        &op_Noop, // &op_Branch_Table,
        &op_Return,
        &op_Noop, // &op_Call,
        &op_Noop, // &op_Call_Indirect,
        &op_Invalid, // Drop is not needed in a register-based VM
        &op_Noop, // &op_Select,
        &op_Noop, // &op_Select_T,
        &op_Invalid, // Local_Get turns into a direct register reference
        &op_Noop, // &op_Local_Set,
        &op_Noop, // &op_Local_Tee,
        &op_Noop, // &op_Global_Get,
        &op_Noop, // &op_Global_Set,
        &op_Noop, // &op_Table_Get,
        &op_Noop, // &op_Table_Set,
        &op_Noop, // &op_I32_Load,
        &op_Noop, // &op_I64_Load,
        &op_Noop, // &op_F32_Load,
        &op_Noop, // &op_F64_Load,
        &op_Noop, // &op_I32_Load8_S,
        &op_Noop, // &op_I32_Load8_U,
        &op_Noop, // &op_I32_Load16_S,
        &op_Noop, // &op_I32_Load16_U,
        &op_Noop, // &op_I64_Load8_S,
        &op_Noop, // &op_I64_Load8_U,
        &op_Noop, // &op_I64_Load16_S,
        &op_Noop, // &op_I64_Load16_U,
        &op_Noop, // &op_I64_Load32_S,
        &op_Noop, // &op_I64_Load32_U,
        &op_Noop, // &op_I32_Store,
        &op_Noop, // &op_I64_Store,
        &op_Noop, // &op_F32_Store,
        &op_Noop, // &op_F64_Store,
        &op_Noop, // &op_I32_Store8,
        &op_Noop, // &op_I32_Store16,
        &op_Noop, // &op_I64_Store8,
        &op_Noop, // &op_I64_Store16,
        &op_Noop, // &op_I64_Store32,
        &op_Noop, // &op_Memory_Size,
        &op_Noop, // &op_Memory_Grow,
        &op_I32_Const,
        &op_I64_Const,
        &op_F32_Const,
        &op_F64_Const,
        &op_I32_Eqz,
        &op_I32_Eq,
        &op_I32_NE,
        &op_I32_LT_S,
        &op_I32_LT_U,
        &op_I32_GT_S,
        &op_I32_GT_U,
        &op_I32_LE_S,
        &op_I32_LE_U,
        &op_I32_GE_S,
        &op_I32_GE_U,
        &op_I64_Eqz,
        &op_I64_Eq,
        &op_I64_NE,
        &op_I64_LT_S,
        &op_I64_LT_U,
        &op_I64_GT_S,
        &op_I64_GT_U,
        &op_I64_LE_S,
        &op_I64_LE_U,
        &op_I64_GE_S,
        &op_I64_GE_U,
        &op_Noop, // &op_F32_EQ,
        &op_Noop, // &op_F32_NE,
        &op_Noop, // &op_F32_LT,
        &op_Noop, // &op_F32_GT,
        &op_Noop, // &op_F32_LE,
        &op_Noop, // &op_F32_GE,
        &op_Noop, // &op_F64_EQ,
        &op_Noop, // &op_F64_NE,
        &op_Noop, // &op_F64_LT,
        &op_Noop, // &op_F64_GT,
        &op_Noop, // &op_F64_LE,
        &op_Noop, // &op_F64_GE,
        &op_I32_Clz,
        &op_I32_Ctz,
        &op_I32_Popcnt,
        &op_I32_Add,
        &op_I32_Sub,
        &op_I32_Mul,
        &op_I32_Div_S,
        &op_I32_Div_U,
        &op_I32_Rem_S,
        &op_I32_Rem_U,
        &op_I32_And,
        &op_I32_Or,
        &op_I32_Xor,
        &op_I32_Shl,
        &op_I32_Shr_S,
        &op_I32_Shr_U,
        &op_I32_Rotl,
        &op_I32_Rotr,
        &op_I64_Clz,
        &op_I64_Ctz,
        &op_I64_Popcnt,
        &op_I64_Add,
        &op_I64_Sub,
        &op_I64_Mul,
        &op_I64_Div_S,
        &op_I64_Div_U,
        &op_I64_Rem_S,
        &op_I64_Rem_U,
        &op_I64_And,
        &op_I64_Or,
        &op_I64_Xor,
        &op_I64_Shl,
        &op_I64_Shr_S,
        &op_I64_Shr_U,
        &op_I64_Rotl,
        &op_I64_Rotr,
        &op_Noop, // &op_F32_Abs,
        &op_Noop, // &op_F32_Neg,
        &op_Noop, // &op_F32_Ceil,
        &op_Noop, // &op_F32_Floor,
        &op_Noop, // &op_F32_Trunc,
        &op_Noop, // &op_F32_Nearest,
        &op_Noop, // &op_F32_Sqrt,
        &op_Noop, // &op_F32_Add,
        &op_Noop, // &op_F32_Sub,
        &op_Noop, // &op_F32_Mul,
        &op_Noop, // &op_F32_Div,
        &op_Noop, // &op_F32_Min,
        &op_Noop, // &op_F32_Max,
        &op_Noop, // &op_F32_Copysign,
        &op_Noop, // &op_F64_Abs,
        &op_Noop, // &op_F64_Neg,
        &op_Noop, // &op_F64_Ceil,
        &op_Noop, // &op_F64_Floor,
        &op_Noop, // &op_F64_Trunc,
        &op_Noop, // &op_F64_Nearest,
        &op_Noop, // &op_F64_Sqrt,
        &op_Noop, // &op_F64_Add,
        &op_Noop, // &op_F64_Sub,
        &op_Noop, // &op_F64_Mul,
        &op_Noop, // &op_F64_Div,
        &op_Noop, // &op_F64_Min,
        &op_Noop, // &op_F64_Max,
        &op_Noop, // &op_F64_Copysign,
        &op_Noop, // &op_I32_Wrap_I64,
        &op_Noop, // &op_I32_Trunc_F32_S,
        &op_Noop, // &op_I32_Trunc_F32_U,
        &op_Noop, // &op_I32_Trunc_F64_S,
        &op_Noop, // &op_I32_Trunc_F64_U,
        &op_Noop, // &op_I64_Extend_I32_S,
        &op_Noop, // &op_I64_Extend_I32_U,
        &op_Noop, // &op_I64_Trunc_F32_S,
        &op_Noop, // &op_I64_Trunc_F32_U,
        &op_Noop, // &op_I64_Trunc_F64_S,
        &op_Noop, // &op_I64_Trunc_F64_U,
        &op_Noop, // &op_F32_Convert_I32_S,
        &op_Noop, // &op_F32_Convert_I32_U,
        &op_Noop, // &op_F32_Convert_I64_S,
        &op_Noop, // &op_F32_Convert_I64_U,
        &op_Noop, // &op_F32_Demote_F64,
        &op_Noop, // &op_F64_Convert_I32_S,
        &op_Noop, // &op_F64_Convert_I32_U,
        &op_Noop, // &op_F64_Convert_I64_S,
        &op_Noop, // &op_F64_Convert_I64_U,
        &op_Noop, // &op_F64_Promote_F32,
        &op_Noop, // &op_I32_Reinterpret_F32,
        &op_Noop, // &op_I64_Reinterpret_F64,
        &op_Noop, // &op_F32_Reinterpret_I32,
        &op_Noop, // &op_F64_Reinterpret_I64,
        &op_I32_Extend8_S,
        &op_I32_Extend16_S,
        &op_I64_Extend8_S,
        &op_I64_Extend16_S,
        &op_I64_Extend32_S,
        &op_Noop, // &op_Ref_Null,
        &op_Noop, // &op_Ref_Is_Null,
        &op_Noop, // &op_Ref_Func,
        &op_Noop, // &op_I32_Trunc_Sat_F32_S,
        &op_Noop, // &op_I32_Trunc_Sat_F32_U,
        &op_Noop, // &op_I32_Trunc_Sat_F64_S,
        &op_Noop, // &op_I32_Trunc_Sat_F64_U,
        &op_Noop, // &op_I64_Trunc_Sat_F32_S,
        &op_Noop, // &op_I64_Trunc_Sat_F32_U,
        &op_Noop, // &op_I64_Trunc_Sat_F64_S,
        &op_Noop, // &op_I64_Trunc_Sat_F64_U,
        &op_Noop, // &op_Memory_Init,
        &op_Noop, // &op_Data_Drop,
        &op_Noop, // &op_Memory_Copy,
        &op_Noop, // &op_Memory_Fill,
        &op_Noop, // &op_Table_Init,
        &op_Noop, // &op_Elem_Drop,
        &op_Noop, // &op_Table_Copy,
        &op_Noop, // &op_Table_Grow,
        &op_Noop, // &op_Table_Size,
        &op_Noop, // &op_Table_Fill,
        &op_Noop, // &op_V128_Load,
        &op_Noop, // &op_V128_Load8x8_S,
        &op_Noop, // &op_V128_Load8x8_U,
        &op_Noop, // &op_V128_Load16x4_S,
        &op_Noop, // &op_V128_Load16x4_U,
        &op_Noop, // &op_V128_Load32x2_S,
        &op_Noop, // &op_V128_Load32x2_U,
        &op_Noop, // &op_V128_Load8_Splat,
        &op_Noop, // &op_V128_Load16_Splat,
        &op_Noop, // &op_V128_Load32_Splat,
        &op_Noop, // &op_V128_Load64_Splat,
        &op_Noop, // &op_V128_Store,
        &op_Noop, // &op_V128_Const,
        &op_Noop, // &op_I8x16_Shuffle,
        &op_Noop, // &op_I8x16_Swizzle,
        &op_Noop, // &op_I8x16_Splat,
        &op_Noop, // &op_I16x8_Splat,
        &op_Noop, // &op_I32x4_Splat,
        &op_Noop, // &op_I64x2_Splat,
        &op_Noop, // &op_F32x4_Splat,
        &op_Noop, // &op_F64x2_Splat,
        &op_Noop, // &op_I8x16_Extract_Lane_S,
        &op_Noop, // &op_I8x16_Extract_Lane_U,
        &op_Noop, // &op_I8x16_Replace_Lane,
        &op_Noop, // &op_I16x8_Extract_Lane_S,
        &op_Noop, // &op_I16x8_Extract_Lane_U,
        &op_Noop, // &op_I16x8_Replace_Lane,
        &op_Noop, // &op_I32x4_Extract_Lane,
        &op_Noop, // &op_I32x4_Replace_Lane,
        &op_Noop, // &op_I64x2_Extract_Lane,
        &op_Noop, // &op_I64x2_Replace_Lane,
        &op_Noop, // &op_F32x4_Extract_Lane,
        &op_Noop, // &op_F32x4_Replace_Lane,
        &op_Noop, // &op_F64x2_Extract_Lane,
        &op_Noop, // &op_F64x2_Replace_Lane,
        &op_Noop, // &op_I8x16_EQ,
        &op_Noop, // &op_I8x16_NE,
        &op_Noop, // &op_I8x16_LT_S,
        &op_Noop, // &op_I8x16_LT_U,
        &op_Noop, // &op_I8x16_GT_S,
        &op_Noop, // &op_I8x16_GT_U,
        &op_Noop, // &op_I8x16_LE_S,
        &op_Noop, // &op_I8x16_LE_U,
        &op_Noop, // &op_I8x16_GE_S,
        &op_Noop, // &op_I8x16_GE_U,
        &op_Noop, // &op_I16x8_EQ,
        &op_Noop, // &op_I16x8_NE,
        &op_Noop, // &op_I16x8_LT_S,
        &op_Noop, // &op_I16x8_LT_U,
        &op_Noop, // &op_I16x8_GT_S,
        &op_Noop, // &op_I16x8_GT_U,
        &op_Noop, // &op_I16x8_LE_S,
        &op_Noop, // &op_I16x8_LE_U,
        &op_Noop, // &op_I16x8_GE_S,
        &op_Noop, // &op_I16x8_GE_U,
        &op_Noop, // &op_I32x4_EQ,
        &op_Noop, // &op_I32x4_NE,
        &op_Noop, // &op_I32x4_LT_S,
        &op_Noop, // &op_I32x4_LT_U,
        &op_Noop, // &op_I32x4_GT_S,
        &op_Noop, // &op_I32x4_GT_U,
        &op_Noop, // &op_I32x4_LE_S,
        &op_Noop, // &op_I32x4_LE_U,
        &op_Noop, // &op_I32x4_GE_S,
        &op_Noop, // &op_I32x4_GE_U,
        &op_Noop, // &op_F32x4_EQ,
        &op_Noop, // &op_F32x4_NE,
        &op_Noop, // &op_F32x4_LT,
        &op_Noop, // &op_F32x4_GT,
        &op_Noop, // &op_F32x4_LE,
        &op_Noop, // &op_F32x4_GE,
        &op_Noop, // &op_F64x2_EQ,
        &op_Noop, // &op_F64x2_NE,
        &op_Noop, // &op_F64x2_LT,
        &op_Noop, // &op_F64x2_GT,
        &op_Noop, // &op_F64x2_LE,
        &op_Noop, // &op_F64x2_GE,
        &op_Noop, // &op_V128_Not,
        &op_Noop, // &op_V128_And,
        &op_Noop, // &op_V128_AndNot,
        &op_Noop, // &op_V128_Or,
        &op_Noop, // &op_V128_Xor,
        &op_Noop, // &op_V128_Bitselect,
        &op_Noop, // &op_V128_AnyTrue,
        &op_Noop, // &op_V128_Load8_Lane,
        &op_Noop, // &op_V128_Load16_Lane,
        &op_Noop, // &op_V128_Load32_Lane,
        &op_Noop, // &op_V128_Load64_Lane,
        &op_Noop, // &op_V128_Store8_Lane,
        &op_Noop, // &op_V128_Store16_Lane,
        &op_Noop, // &op_V128_Store32_Lane,
        &op_Noop, // &op_V128_Store64_Lane,
        &op_Noop, // &op_V128_Load32_Zero,
        &op_Noop, // &op_V128_Load64_Zero,
        &op_Noop, // &op_F32x4_Demote_F64x2_Zero,
        &op_Noop, // &op_F64x2_Promote_Low_F32x4,
        &op_Noop, // &op_I8x16_Abs,
        &op_Noop, // &op_I8x16_Neg,
        &op_Noop, // &op_I8x16_Popcnt,
        &op_Noop, // &op_I8x16_AllTrue,
        &op_Noop, // &op_I8x16_Bitmask,
        &op_Noop, // &op_I8x16_Narrow_I16x8_S,
        &op_Noop, // &op_I8x16_Narrow_I16x8_U,
        &op_Noop, // &op_F32x4_Ceil,
        &op_Noop, // &op_F32x4_Floor,
        &op_Noop, // &op_F32x4_Trunc,
        &op_Noop, // &op_F32x4_Nearest,
        &op_Noop, // &op_I8x16_Shl,
        &op_Noop, // &op_I8x16_Shr_S,
        &op_Noop, // &op_I8x16_Shr_U,
        &op_Noop, // &op_I8x16_Add,
        &op_Noop, // &op_I8x16_Add_Sat_S,
        &op_Noop, // &op_I8x16_Add_Sat_U,
        &op_Noop, // &op_I8x16_Sub,
        &op_Noop, // &op_I8x16_Sub_Sat_S,
        &op_Noop, // &op_I8x16_Sub_Sat_U,
        &op_Noop, // &op_F64x2_Ceil,
        &op_Noop, // &op_F64x2_Floor,
        &op_Noop, // &op_I8x16_Min_S,
        &op_Noop, // &op_I8x16_Min_U,
        &op_Noop, // &op_I8x16_Max_S,
        &op_Noop, // &op_I8x16_Max_U,
        &op_Noop, // &op_F64x2_Trunc,
        &op_Noop, // &op_I8x16_Avgr_U,
        &op_Noop, // &op_I16x8_Extadd_Pairwise_I8x16_S,
        &op_Noop, // &op_I16x8_Extadd_Pairwise_I8x16_U,
        &op_Noop, // &op_I32x4_Extadd_Pairwise_I16x8_S,
        &op_Noop, // &op_I32x4_Extadd_Pairwise_I16x8_U,
        &op_Noop, // &op_I16x8_Abs,
        &op_Noop, // &op_I16x8_Neg,
        &op_Noop, // &op_I16x8_Q15mulr_Sat_S,
        &op_Noop, // &op_I16x8_AllTrue,
        &op_Noop, // &op_I16x8_Bitmask,
        &op_Noop, // &op_I16x8_Narrow_I32x4_S,
        &op_Noop, // &op_I16x8_Narrow_I32x4_U,
        &op_Noop, // &op_I16x8_Extend_Low_I8x16_S,
        &op_Noop, // &op_I16x8_Extend_High_I8x16_S,
        &op_Noop, // &op_I16x8_Extend_Low_I8x16_U,
        &op_Noop, // &op_I16x8_Extend_High_I8x16_U,
        &op_Noop, // &op_I16x8_Shl,
        &op_Noop, // &op_I16x8_Shr_S,
        &op_Noop, // &op_I16x8_Shr_U,
        &op_Noop, // &op_I16x8_Add,
        &op_Noop, // &op_I16x8_Add_Sat_S,
        &op_Noop, // &op_I16x8_Add_Sat_U,
        &op_Noop, // &op_I16x8_Sub,
        &op_Noop, // &op_I16x8_Sub_Sat_S,
        &op_Noop, // &op_I16x8_Sub_Sat_U,
        &op_Noop, // &op_F64x2_Nearest,
        &op_Noop, // &op_I16x8_Mul,
        &op_Noop, // &op_I16x8_Min_S,
        &op_Noop, // &op_I16x8_Min_U,
        &op_Noop, // &op_I16x8_Max_S,
        &op_Noop, // &op_I16x8_Max_U,
        &op_Noop, // &op_I16x8_Avgr_U,
        &op_Noop, // &op_I16x8_Extmul_Low_I8x16_S,
        &op_Noop, // &op_I16x8_Extmul_High_I8x16_S,
        &op_Noop, // &op_I16x8_Extmul_Low_I8x16_U,
        &op_Noop, // &op_I16x8_Extmul_High_I8x16_U,
        &op_Noop, // &op_I32x4_Abs,
        &op_Noop, // &op_I32x4_Neg,
        &op_Noop, // &op_I32x4_AllTrue,
        &op_Noop, // &op_I32x4_Bitmask,
        &op_Noop, // &op_I32x4_Extend_Low_I16x8_S,
        &op_Noop, // &op_I32x4_Extend_High_I16x8_S,
        &op_Noop, // &op_I32x4_Extend_Low_I16x8_U,
        &op_Noop, // &op_I32x4_Extend_High_I16x8_U,
        &op_Noop, // &op_I32x4_Shl,
        &op_Noop, // &op_I32x4_Shr_S,
        &op_Noop, // &op_I32x4_Shr_U,
        &op_Noop, // &op_I32x4_Add,
        &op_Noop, // &op_I32x4_Sub,
        &op_Noop, // &op_I32x4_Mul,
        &op_Noop, // &op_I32x4_Min_S,
        &op_Noop, // &op_I32x4_Min_U,
        &op_Noop, // &op_I32x4_Max_S,
        &op_Noop, // &op_I32x4_Max_U,
        &op_Noop, // &op_I32x4_Dot_I16x8_S,
        &op_Noop, // &op_I32x4_Extmul_Low_I16x8_S,
        &op_Noop, // &op_I32x4_Extmul_High_I16x8_S,
        &op_Noop, // &op_I32x4_Extmul_Low_I16x8_U,
        &op_Noop, // &op_I32x4_Extmul_High_I16x8_U,
        &op_Noop, // &op_I64x2_Abs,
        &op_Noop, // &op_I64x2_Neg,
        &op_Noop, // &op_I64x2_AllTrue,
        &op_Noop, // &op_I64x2_Bitmask,
        &op_Noop, // &op_I64x2_Extend_Low_I32x4_S,
        &op_Noop, // &op_I64x2_Extend_High_I32x4_S,
        &op_Noop, // &op_I64x2_Extend_Low_I32x4_U,
        &op_Noop, // &op_I64x2_Extend_High_I32x4_U,
        &op_Noop, // &op_I64x2_Shl,
        &op_Noop, // &op_I64x2_Shr_S,
        &op_Noop, // &op_I64x2_Shr_U,
        &op_Noop, // &op_I64x2_Add,
        &op_Noop, // &op_I64x2_Sub,
        &op_Noop, // &op_I64x2_Mul,
        &op_Noop, // &op_I64x2_EQ,
        &op_Noop, // &op_I64x2_NE,
        &op_Noop, // &op_I64x2_LT_S,
        &op_Noop, // &op_I64x2_GT_S,
        &op_Noop, // &op_I64x2_LE_S,
        &op_Noop, // &op_I64x2_GE_S,
        &op_Noop, // &op_I64x2_Extmul_Low_I32x4_S,
        &op_Noop, // &op_I64x2_Extmul_High_I32x4_S,
        &op_Noop, // &op_I64x2_Extmul_Low_I32x4_U,
        &op_Noop, // &op_I64x2_Extmul_High_I32x4_U,
        &op_Noop, // &op_F32x4_Abs,
        &op_Noop, // &op_F32x4_Neg,
        &op_Noop, // &op_F32x4_Sqrt,
        &op_Noop, // &op_F32x4_Add,
        &op_Noop, // &op_F32x4_Sub,
        &op_Noop, // &op_F32x4_Mul,
        &op_Noop, // &op_F32x4_Div,
        &op_Noop, // &op_F32x4_Min,
        &op_Noop, // &op_F32x4_Max,
        &op_Noop, // &op_F32x4_PMin,
        &op_Noop, // &op_F32x4_PMax,
        &op_Noop, // &op_F64x2_Abs,
        &op_Noop, // &op_F64x2_Neg,
        &op_Noop, // &op_F64x2_Sqrt,
        &op_Noop, // &op_F64x2_Add,
        &op_Noop, // &op_F64x2_Sub,
        &op_Noop, // &op_F64x2_Mul,
        &op_Noop, // &op_F64x2_Div,
        &op_Noop, // &op_F64x2_Min,
        &op_Noop, // &op_F64x2_Max,
        &op_Noop, // &op_F64x2_PMin,
        &op_Noop, // &op_F64x2_PMax,
        &op_Noop, // &op_F32x4_Trunc_Sat_F32x4_S,
        &op_Noop, // &op_F32x4_Trunc_Sat_F32x4_U,
        &op_Noop, // &op_F32x4_Convert_I32x4_S,
        &op_Noop, // &op_F32x4_Convert_I32x4_U,
        &op_Noop, // &op_I32x4_Trunc_Sat_F64x2_S_Zero,
        &op_Noop, // &op_I32x4_Trunc_Sat_F64x2_U_Zero,
        &op_Noop, // &op_F64x2_Convert_Low_I32x4_S,
        &op_Noop, // &op_F64x2_Convert_Low_I32x4_U,
    };

    fn preamble(name: []const u8, pc: u32, ms: *const MachineState) TrapError!void {
        ms.traceInstruction(name, pc);
    }

    fn run(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try @call(.always_tail, lookup(code[pc].opcode), .{ pc, code, ms });
    }

    fn lookup(opcode: Opcode) InstructionFunc {
        return opcodeToFuncTable[@intFromEnum(opcode)];
    }

    // TODO move these to a common file so we can share implementations with the stack VM
    const OpHelpers = struct {
        fn bitCastUnsignedType(comptime T: type) type {
            return switch (T) {
                i32 => u32,
                i64 => u64,
                else => unreachable,
            };
        }

        fn bitCastUnsigned(v: anytype) bitCastUnsignedType(@TypeOf(v)) {
            return @as(bitCastUnsignedType(@TypeOf(v)), @bitCast(v));
        }

        fn bitCastSignedType(comptime T: type) type {
            return switch (T) {
                u32 => i32,
                u64 => i64,
                else => unreachable,
            };
        }

        fn bitCastSigned(v: anytype) bitCastSignedType(@TypeOf(v)) {
            return @as(bitCastSignedType(@TypeOf(v)), @bitCast(v));
        }

        fn unaryOp(comptime T: type, comptime opcode: Opcode, registers: []const u32, ms: *MachineState) TrapError!void {
            const r0 = registers[0];
            const r1 = registers[1];

            switch (T) {
                i32, i64 => {
                    const v = ms.getType(T, r0);
                    const out: T = switch (opcode) {
                        .I32_Eqz, .I64_Eqz => if (v == 0) 1 else 0,
                        .I32_Clz, .I64_Clz => @clz(v),
                        .I32_Ctz, .I64_Ctz => @ctz(v),
                        .I32_Popcnt, .I64_Popcnt => @popCount(v),
                        .I32_Extend8_S, .I64_Extend8_S => @as(i8, @truncate(v)),
                        .I32_Extend16_S, .I64_Extend16_S => @as(i16, @truncate(v)),
                        .I64_Extend32_S => @as(i32, @truncate(v)),
                        else => unreachable,
                    };
                    ms.setType(T, r1, out);
                },
                else => unreachable,
            }
        }

        fn binaryOp(comptime T: type, comptime opcode: Opcode, registers: []const u32, ms: *MachineState) TrapError!void {
            const r0 = registers[0];
            const r1 = registers[1];
            const r2 = registers[2];

            switch (T) {
                i32, i64 => {
                    const utype = bitCastUnsignedType(T);
                    const type_bitcount = @typeInfo(T).Int.bits;

                    const v0 = ms.getType(T, r0);
                    const v1 = ms.getType(T, r1);
                    const out: T = switch (opcode) {
                        .I32_Eq, .I64_Eq => if (v0 == v1) 1 else 0,
                        .I32_NE, .I64_NE => if (v0 != v1) 1 else 0,
                        .I32_LT_S, .I64_LT_S => if (v0 < v1) 1 else 0,
                        .I32_LT_U, .I64_LT_U => if (bitCastUnsigned(v0) < bitCastUnsigned(v1)) 1 else 0,
                        .I32_GT_S, .I64_GT_S => if (v0 > v1) 1 else 0,
                        .I32_GT_U, .I64_GT_U => if (bitCastUnsigned(v0) > bitCastUnsigned(v1)) 1 else 0,
                        .I32_LE_S, .I64_LE_S => if (v0 <= v1) 1 else 0,
                        .I32_LE_U, .I64_LE_U => if (bitCastUnsigned(v0) <= bitCastUnsigned(v1)) 1 else 0,
                        .I32_GE_S, .I64_GE_S => if (v0 >= v1) 1 else 0,
                        .I32_GE_U, .I64_GE_U => if (bitCastUnsigned(v0) >= bitCastUnsigned(v1)) 1 else 0,
                        .I32_Add, .I64_Add => v0 +% v1,
                        .I32_Sub, .I64_Sub => v0 -% v1,
                        .I32_Mul, .I64_Mul => v0 *% v1,
                        .I32_Div_S, .I64_Div_S => blk: {
                            if (v1 == 0) {
                                return TrapError.TrapIntegerDivisionByZero;
                            }
                            if (v0 == std.math.minInt(T) and v1 == -1) {
                                return TrapError.TrapIntegerOverflow;
                            }
                            break :blk @divTrunc(v0, v1);
                        },
                        .I32_Div_U, .I64_Div_U => blk: {
                            if (v1 == 0) {
                                return TrapError.TrapIntegerDivisionByZero;
                            }
                            const v0_unsigned: utype = bitCastUnsigned(v0);
                            const v1_unsigned: utype = bitCastUnsigned(v1);
                            const unsigned = @divFloor(v0_unsigned, v1_unsigned);
                            break :blk bitCastSigned(unsigned);
                        },
                        .I32_Rem_S, .I64_Rem_S => blk: {
                            if (v1 == 0) {
                                return TrapError.TrapIntegerDivisionByZero;
                            }
                            break :blk @rem(v0, @as(i32, @intCast(@abs(v1))));
                        },
                        .I32_Rem_U, .I64_Rem_U => blk: {
                            if (v1 == 0) {
                                return TrapError.TrapIntegerDivisionByZero;
                            }
                            const v0_unsigned: utype = bitCastUnsigned(v0);
                            const v1_unsigned: utype = bitCastUnsigned(v1);
                            const unsigned = @rem(v0_unsigned, v1_unsigned);
                            break :blk bitCastSigned(unsigned);
                        },
                        .I32_And, .I64_And => bitCastSigned(bitCastUnsigned(v0) & bitCastUnsigned(v1)),
                        .I32_Or, .I64_Or => bitCastSigned(bitCastUnsigned(v0) | bitCastUnsigned(v1)),
                        .I32_Xor, .I64_Xor => bitCastSigned(bitCastUnsigned(v0) ^ bitCastUnsigned(v1)),
                        .I32_Shl, .I64_Shl => blk: {
                            const shift_unsafe = v1;
                            const shift = @mod(shift_unsafe, type_bitcount);
                            break :blk std.math.shl(T, v0, shift);
                        },
                        .I32_Shr_S, .I64_Shr_S => blk: {
                            const shift_unsafe = v1;
                            const shift = @mod(shift_unsafe, type_bitcount);
                            break :blk std.math.shr(T, v0, shift);
                        },
                        .I32_Shr_U, .I64_Shr_U => blk: {
                            const shift_unsafe = bitCastUnsigned(v1);
                            const int = bitCastUnsigned(v0);
                            const shift = @mod(shift_unsafe, type_bitcount);
                            break :blk bitCastSigned(std.math.shr(utype, int, shift));
                        },
                        .I32_Rotl, .I64_Rotl => blk: {
                            const rot = bitCastUnsigned(v1);
                            const int = bitCastUnsigned(v0);
                            break :blk bitCastSigned(std.math.rotl(utype, int, rot));
                        },
                        .I32_Rotr, .I64_Rotr => blk: {
                            const rot = bitCastUnsigned(v1);
                            const int = bitCastUnsigned(v0);
                            break :blk bitCastSigned(std.math.rotr(utype, int, rot));
                        },
                        else => unreachable,
                    };
                    ms.setType(T, r2, out);
                },
                else => unreachable,
            }
        }
    };

    fn op_Invalid(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        std.debug.print(">>>>>>>> op_Invalid for instr: {}\n", .{code[pc]});
        try preamble("Invalid", pc, ms);
        // _ = code;
        unreachable;
    }

    fn op_Unreachable(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("Unreachable", pc, ms);
        _ = code;
        return error.TrapUnreachable;
    }

    // fn op_DebugTrap(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
    // unreachable;
    // }

    fn op_Noop(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("Noop", pc, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_End(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("End", pc, ms);
        _ = code;

        // TODO fill out
    }

    fn op_Return(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("Return", pc, ms);
        _ = code;
    }

    fn op_I32_Const(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Const", pc, ms);
        ms.setI32(code[pc].registers[0], code[pc].immediate.ValueI32);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Const(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Const", pc, ms);
        ms.setI64(code[pc].registers[0], code[pc].immediate.ValueI64);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_F32_Const(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("F32_Const", pc, ms);
        ms.setF32(code[pc].registers[0], code[pc].immediate.ValueF32);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_F64_Const(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("F64_Const", pc, ms);
        ms.setF64(code[pc].registers[0], code[pc].immediate.ValueF64);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Eqz(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Eqz", pc, ms);
        try OpHelpers.unaryOp(i32, Opcode.I32_Eqz, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Eq(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Eq", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Eq, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_NE(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_NE", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_NE, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_LT_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_LT_S", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_LT_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_LT_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_LT_U", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_LT_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_GT_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_GT_S", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_GT_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_GT_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_GT_U", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_GT_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_LE_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_LE_S", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_LE_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_LE_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_LE_U", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_LE_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_GE_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_GE_S", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_GE_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_GE_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_GE_U", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_GE_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Eqz(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Eqz", pc, ms);
        try OpHelpers.unaryOp(i64, Opcode.I64_Eqz, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Eq(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Eq", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Eq, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_NE(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_NE", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_NE, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_LT_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_LT_S", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_LT_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_LT_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_LT_U", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_LT_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_GT_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_GT_S", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_GT_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_GT_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_GT_U", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_GT_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_LE_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_LE_S", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_LE_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_LE_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_LE_U", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_LE_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_GE_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_GE_S", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_GE_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_GE_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_GE_U", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_GE_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    // &op_F32_EQ,
    // &op_F32_NE,
    // &op_F32_LT,
    // &op_F32_GT,
    // &op_F32_LE,
    // &op_F32_GE,
    // &op_F64_EQ,
    // &op_F64_NE,
    // &op_F64_LT,
    // &op_F64_GT,
    // &op_F64_LE,
    // &op_F64_GE,

    fn op_I32_Clz(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Clz", pc, ms);
        try OpHelpers.unaryOp(i32, Opcode.I32_Clz, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Ctz(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Ctz", pc, ms);
        try OpHelpers.unaryOp(i32, Opcode.I32_Ctz, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Popcnt(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Popcnt", pc, ms);
        try OpHelpers.unaryOp(i32, Opcode.I32_Popcnt, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Add(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Add", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Add, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Sub(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Sub", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Sub, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Mul(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Mul", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Mul, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Div_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Div_S", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Div_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Div_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Div_U", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Div_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Rem_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Rem_S", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Rem_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Rem_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Rem_U", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Rem_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_And(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_And", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_And, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Or(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Or", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Or, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Xor(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Xor", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Xor, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Shl(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Shl", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Shl, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Shr_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Shr_S", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Shr_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Shr_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Shr_U", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Shr_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Rotl(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Rotl", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Rotl, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Rotr(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Rotr", pc, ms);
        try OpHelpers.binaryOp(i32, Opcode.I32_Rotr, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Clz(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Clz", pc, ms);
        try OpHelpers.unaryOp(i64, Opcode.I64_Clz, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Ctz(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Ctz", pc, ms);
        try OpHelpers.unaryOp(i64, Opcode.I64_Ctz, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Popcnt(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Popcnt", pc, ms);
        try OpHelpers.unaryOp(i64, Opcode.I64_Popcnt, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Add(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Add", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Add, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Sub(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Sub", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Sub, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Mul(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Mul", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Mul, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Div_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Div_S", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Div_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Div_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Div_U", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Div_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Rem_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Rem_S", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Rem_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Rem_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Rem_U", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Rem_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_And(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_And", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_And, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Or(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Or", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Or, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Xor(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Xor", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Xor, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Shl(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Shl", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Shl, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Shr_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Shr_S", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Shr_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Shr_U(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Shr_U", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Shr_U, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Rotl(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Rotl", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Rotl, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Rotr(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Rotr", pc, ms);
        try OpHelpers.binaryOp(i64, Opcode.I64_Rotr, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    // &op_F32_Abs,
    // &op_F32_Neg,
    // &op_F32_Ceil,
    // &op_F32_Floor,
    // &op_F32_Trunc,
    // &op_F32_Nearest,
    // &op_F32_Sqrt,
    // &op_F32_Add,
    // &op_F32_Sub,
    // &op_F32_Mul,
    // &op_F32_Div,
    // &op_F32_Min,
    // &op_F32_Max,
    // &op_F32_Copysign,
    // &op_F64_Abs,
    // &op_F64_Neg,
    // &op_F64_Ceil,
    // &op_F64_Floor,
    // &op_F64_Trunc,
    // &op_F64_Nearest,
    // &op_F64_Sqrt,
    // &op_F64_Add,
    // &op_F64_Sub,
    // &op_F64_Mul,
    // &op_F64_Div,
    // &op_F64_Min,
    // &op_F64_Max,
    // &op_F64_Copysign,
    // &op_I32_Wrap_I64,
    // &op_I32_Trunc_F32_S,
    // &op_I32_Trunc_F32_U,
    // &op_I32_Trunc_F64_S,
    // &op_I32_Trunc_F64_U,
    // &op_I64_Extend_I32_S,
    // &op_I64_Extend_I32_U,
    // &op_I64_Trunc_F32_S,
    // &op_I64_Trunc_F32_U,
    // &op_I64_Trunc_F64_S,
    // &op_I64_Trunc_F64_U,
    // &op_F32_Convert_I32_S,
    // &op_F32_Convert_I32_U,
    // &op_F32_Convert_I64_S,
    // &op_F32_Convert_I64_U,
    // &op_F32_Demote_F64,
    // &op_F64_Convert_I32_S,
    // &op_F64_Convert_I32_U,
    // &op_F64_Convert_I64_S,
    // &op_F64_Convert_I64_U,
    // &op_F64_Promote_F32,
    // &op_I32_Reinterpret_F32,
    // &op_I64_Reinterpret_F64,
    // &op_F32_Reinterpret_I32,
    // &op_F64_Reinterpret_I64,

    fn op_I32_Extend8_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Extend8_S", pc, ms);
        try OpHelpers.unaryOp(i32, Opcode.I32_Extend8_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I32_Extend16_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I32_Extend16_S", pc, ms);
        try OpHelpers.unaryOp(i32, Opcode.I32_Extend16_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Extend8_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Extend8_S", pc, ms);
        try OpHelpers.unaryOp(i64, Opcode.I64_Extend8_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Extend16_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Extend16_S", pc, ms);
        try OpHelpers.unaryOp(i64, Opcode.I64_Extend16_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }

    fn op_I64_Extend32_S(pc: u32, code: [*]const RegInstruction, ms: *MachineState) TrapError!void {
        try preamble("I64_Extend32_S", pc, ms);
        try OpHelpers.unaryOp(i64, Opcode.I64_Extend32_S, code[pc].registers, ms);
        try @call(.always_tail, InstructionFuncs.lookup(code[pc + 1].opcode), .{ pc + 1, code, ms });
    }
};

const FunctionStore = struct {
    local_types: std.ArrayList(ValType),
    instructions: std.ArrayList(RegInstruction),
    instances: std.ArrayList(FunctionInstance),
    registers: StableArray(u32),

    fn init(allocator: std.mem.Allocator) FunctionStore {
        return .{
            .local_types = std.ArrayList(ValType).init(allocator),
            .instructions = std.ArrayList(RegInstruction).init(allocator),
            .instances = std.ArrayList(FunctionInstance).init(allocator),
            .registers = StableArray(u32).init(1024 * 1024 * 1), // 1 MB
        };
    }

    fn deinit(store: *FunctionStore) void {
        store.local_types.deinit();
        store.instructions.deinit();
        store.instances.deinit();
    }
};

pub const RegisterVM = struct {
    functions: FunctionStore,
    ms: MachineState,

    fn fromVM(vm: *VM) *RegisterVM {
        return @as(*RegisterVM, @alignCast(@ptrCast(vm.impl)));
    }

    pub fn init(vm: *VM) void {
        var self: *RegisterVM = fromVM(vm);

        self.functions = FunctionStore.init(vm.allocator);
        self.ms = MachineState.init(vm.allocator);
    }

    pub fn deinit(vm: *VM) void {
        var self: *RegisterVM = fromVM(vm);

        self.functions.local_types.deinit();
        self.functions.instructions.deinit();
        self.functions.instances.deinit();
        self.ms.deinit();
    }

    pub fn instantiate(vm: *VM, module: *ModuleInstance, opts: ModuleInstantiateOpts) anyerror!void {
        var self: *RegisterVM = fromVM(vm);

        const stack_size = if (opts.stack_size > 0) opts.stack_size else 1024 * 128;
        const stack_size_f = @as(f64, @floatFromInt(stack_size));

        try self.ms.allocMemory(.{
            .max_registers = @as(usize, @intFromFloat(stack_size_f * 0.85)),
            .max_labels = @as(usize, @intFromFloat(stack_size_f * 0.14)),
            .max_frames = @as(usize, @intFromFloat(stack_size_f * 0.01)),
        });

        var compiler = FunctionCompiler.init(vm.allocator, module.module_def);
        defer compiler.deinit();

        try compiler.compile(&self.functions);

        // wasm bytecode -> IR graph -> register-assigned IR graph -> []RegInstruction

        // TODO create functions?

        // return error.Unimplemented;
    }

    pub fn invoke(vm: *VM, module: *ModuleInstance, handle: FunctionHandle, params: [*]const Val, returns: [*]Val, opts: InvokeOpts) anyerror!void {
        var self: *RegisterVM = fromVM(vm);

        std.debug.assert(handle.type == .Export);

        std.debug.print("========== INVOKE ===========\n", .{});

        const num_imports = module.module_def.imports.functions.items.len;
        const func_instance_index = handle.index - num_imports;

        // if (func_index >= num_imports) {
        //     try self.invokeInternal(module, instance_index, params, returns);
        // } else {
        //     unreachable; // TODO
        //     // try invokeImportInternal(module, func_index, params, returns, .{});
        // }

        // const num_imports = module.module_def.imports.functions.items.len;
        // if (func_index >= num_imports) {
        //     const instance_index = func_index - num_imports;
        //     try self.invokeInternal(module, instance_index, params, returns);
        // } else {
        //     unreachable; // TODO
        //     // try invokeImportInternal(module, func_index, params, returns, .{});
        // }

        const func: FunctionInstance = self.functions.instances.items[func_instance_index];
        const func_def: FunctionDefinition = module.module_def.functions.items[func.def_index];

        const params_slice = params[0..func.num_params];
        const returns_slice = returns[0..func.num_returns];

        // Ensure any leftover state doesn't pollute this invoke. Can happen if the previous invoke returned an error.
        self.ms.reset();

        try self.ms.pushFrame(func, module);
        try self.ms.pushLabel(func.num_returns, @intCast(func_def.continuation));
        for (params_slice, 0..) |v, i| {
            // need to set in reverse order to follow the stack convention
            self.ms.setVal(@intCast(params_slice.len - 1 - i), v);
        }

        DebugTrace.traceFunction(module, self.ms.num_frames, func.def_index);

        try InstructionFuncs.run(@intCast(func.instructions_begin), self.functions.instructions.items.ptr, &self.ms);

        // const total = returns_slice.len;
        const return_registers = self.ms.registers[0..func.num_returns];
        for (returns_slice, return_registers) |*ret, v| {
            ret.* = v;
        }

        // if (returns_slice.len > 0) {
        //     var index: i32 = @as(i32, @intCast(returns_slice.len - 1));
        //     while (index >= 0) {
        //         returns_slice[@as(usize, @intCast(index))] = self.ms.registers[index];
        //         index -= 1;
        //     }
        // }

        // _ = module;
        // _ = handle;
        // _ = params;
        // _ = returns;
        _ = opts;
        // return error.Unimplemented;
    }

    pub fn invokeWithIndex(vm: *VM, module: *ModuleInstance, func_index: usize, params: [*]const Val, returns: [*]Val) anyerror!void {
        _ = vm;
        _ = module;
        _ = func_index;
        _ = params;
        _ = returns;
        return error.Unimplemented;
    }

    pub fn resumeInvoke(vm: *VM, module: *ModuleInstance, returns: []Val, opts: ResumeInvokeOpts) anyerror!void {
        _ = vm;
        _ = module;
        _ = returns;
        _ = opts;
        return error.Unimplemented;
    }

    pub fn step(vm: *VM, module: *ModuleInstance, returns: []Val) anyerror!void {
        _ = vm;
        _ = module;
        _ = returns;
        return error.Unimplemented;
    }

    pub fn setDebugTrap(vm: *VM, module: *ModuleInstance, wasm_address: u32, mode: DebugTrapInstructionMode) anyerror!bool {
        _ = vm;
        _ = module;
        _ = wasm_address;
        _ = mode;
        return error.Unimplemented;
    }

    pub fn formatBacktrace(vm: *VM, indent: u8, allocator: std.mem.Allocator) anyerror!std.ArrayList(u8) {
        _ = vm;
        _ = indent;
        _ = allocator;
        return error.Unimplemented;
    }

    pub fn findFuncTypeDef(vm: *VM, module: *ModuleInstance, local_func_index: usize) *const FunctionTypeDefinition {
        var self: *RegisterVM = fromVM(vm);
        return self.functions.instances.items[local_func_index].typeDefinition(module.module_def.*);
    }
};

fn runTestWithViz(wasm_filepath: []const u8, viz_dir: []const u8) !void {
    var allocator = std.testing.allocator;

    var cwd = std.fs.cwd();
    const wasm_data: []u8 = try cwd.readFileAlloc(allocator, wasm_filepath, 1024 * 1024 * 128);
    defer allocator.free(wasm_data);

    const module_def_opts = def.ModuleDefinitionOpts{
        .debug_name = std.fs.path.basename(wasm_filepath),
    };
    var module_def = try ModuleDefinition.create(allocator, module_def_opts);
    defer module_def.destroy();

    try module_def.decode(wasm_data);

    var compiler = FunctionCompiler.init(allocator, module_def);
    defer compiler.deinit();

    var store = FunctionStore.init(allocator);
    defer store.deinit();

    try compiler.compile(&store);
    for (compiler.functions.items, 0..) |func, i| {
        var viz_path_buffer: [256]u8 = undefined;
        const viz_path = std.fmt.bufPrint(&viz_path_buffer, "{s}\\viz_{}.txt", .{ viz_dir, i }) catch unreachable;
        std.debug.print("gen graph for func {}\n", .{i});
        try func.dumpVizGraph(viz_path, module_def.*, std.testing.allocator);
    }
}

// test "ir1" {
//     const filename =
//         // \\E:\Dev\zig_projects\bytebox\test\wasm\br_table\br_table.0.wasm
//         \\E:\Dev\zig_projects\bytebox\test\wasm\return\return.0.wasm
//         // \\E:\Dev\third_party\zware\test\fact.wasm
//         // \\E:\Dev\zig_projects\bytebox\test\wasm\i32\i32.0.wasm
//     ;
//     const viz_dir =
//         \\E:\Dev\zig_projects\bytebox\viz
//     ;
//     try runTestWithViz(filename, viz_dir);

//     // var allocator = std.testing.allocator;

//     // var cwd = std.fs.cwd();
//     // var wasm_data: []u8 = try cwd.readFileAlloc(allocator, filename, 1024 * 1024 * 128);
//     // defer allocator.free(wasm_data);

//     // const module_def_opts = def.ModuleDefinitionOpts{
//     //     .debug_name = std.fs.path.basename(filename),
//     // };
//     // var module_def = ModuleDefinition.init(allocator, module_def_opts);
//     // defer module_def.deinit();

//     // try module_def.decode(wasm_data);

//     // var compiler = FunctionCompiler.init(allocator, &module_def);
//     // defer compiler.deinit();
//     // try compiler.compile();
//     // for (compiler.functions.items, 0..) |func, i| {
//     //     var viz_path_buffer: [256]u8 = undefined;
//     //     const path_format =
//     //         \\E:\Dev\zig_projects\bytebox\viz\viz_{}.txt
//     //     ;
//     //     const viz_path = std.fmt.bufPrint(&viz_path_buffer, path_format, .{i}) catch unreachable;
//     //     std.debug.print("gen graph for func {}\n", .{i});
//     //     try func.dumpVizGraph(viz_path, module_def, std.testing.allocator);
//     // }
// }

// test "ir2" {
//     const filename =
//         // \\E:\Dev\zig_projects\bytebox\test\wasm\br_table\br_table.0.wasm
//         \\E:\Dev\zig_projects\bytebox\test\reg\add.wasm
//         // \\E:\Dev\third_party\zware\test\fact.wasm
//         // \\E:\Dev\zig_projects\bytebox\test\wasm\i32\i32.0.wasm
//     ;
//     const viz_dir =
//         \\E:\Dev\zig_projects\bytebox\test\reg\
//     ;
//     try runTestWithViz(filename, viz_dir);
// }
