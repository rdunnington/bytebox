const std = @import("std");
const bytebox = @import("bytebox");
const Val = bytebox.Val;
const Timer = std.time.Timer;

pub const std_options: std.Options = .{
    .log_level = .info,
};

const Benchmark = struct {
    name: []const u8,
    filename: []const u8,
    param: i32,
};

fn elapsedMilliseconds(timer: *std.time.Timer) f64 {
    const ns_elapsed: f64 = @as(f64, @floatFromInt(timer.read()));
    const ms_elapsed = ns_elapsed / 1000000.0;
    return ms_elapsed;
}

fn run(allocator: std.mem.Allocator, benchmark: Benchmark) !void {
    var cwd = std.fs.cwd();
    const wasm_data: []u8 = try cwd.readFileAlloc(allocator, benchmark.filename, 1024 * 64); // Our wasm programs aren't very large

    var timer = try Timer.start();

    var module_def = try bytebox.createModuleDefinition(allocator, .{});
    defer module_def.destroy();
    try module_def.decode(wasm_data);

    var module_instance = try bytebox.createModuleInstance(.Stack, module_def, allocator);
    defer module_instance.destroy();
    try module_instance.instantiate(.{});

    const handle = try module_instance.getFunctionHandle("run");
    var input = [1]Val{.{ .I32 = benchmark.param }};
    var output = [1]Val{.{ .I32 = 0 }};
    try module_instance.invoke(handle, &input, &output, .{});

    const ms_elapsed: f64 = elapsedMilliseconds(&timer);
    std.log.info("{s} decode+instantiate+run took {d}ms\n", .{ benchmark.name, ms_elapsed });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator: std.mem.Allocator = gpa.allocator();

    const benchmarks = [_]Benchmark{ .{
        .name = "add-one",
        .filename = "zig-out/bin/add-one.wasm",
        .param = 123456789,
    }, .{
        .name = "fibonacci",
        .filename = "zig-out/bin/fibonacci.wasm",
        .param = 39,
    }, .{
        .name = "mandelbrot",
        .filename = "zig-out/bin/mandelbrot.wasm",
        .param = 20,
    } };

    for (benchmarks) |benchmark| {
        run(allocator, benchmark) catch |e| {
            std.log.err("{s} 'run' invocation failed with error: {}\n", .{ benchmark.name, e });
            return e;
        };
    }
}
