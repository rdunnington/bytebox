const std = @import("std");
const wasm = @import("wasm");
const Val = wasm.Val;
const Timer = std.time.Timer;

const Benchmark = struct {
    name: []const u8,
    filename: []const u8,
    param: i32,
};

fn elapsedMilliseconds(timer: *std.time.Timer) f64 {
    var ns_elapsed: f64 = @intToFloat(f64, timer.read());
    const ms_elapsed = ns_elapsed / 1000000.0;
    return ms_elapsed;
}

fn run(allocator: std.mem.Allocator, benchmark: Benchmark) !void {
    var cwd = std.fs.cwd();
    var wasm_data: []u8 = try cwd.readFileAlloc(allocator, benchmark.filename, 1024 * 64); // Our wasm programs aren't very large

    var timer = try Timer.start();

    var module_def = try wasm.ModuleDefinition.init(wasm_data, allocator);
    var module_instance = wasm.ModuleInstance.init(&module_def, allocator);
    try module_instance.instantiate(null);

    var input = [1]Val{.{ .I32 = benchmark.param }};
    var output = [1]Val{.{ .I32 = 0 }};
    try module_instance.invoke("run", &input, &output);

    const ms_elapsed: f64 = elapsedMilliseconds(&timer);
    std.log.info("{s} decode+instantiate+run took {d}ms\n", .{ benchmark.name, ms_elapsed });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator: std.mem.Allocator = gpa.allocator();

    const benchmarks = [_]Benchmark{ .{
        .name = "add-one",
        .filename = "zig-out/lib/add-one.wasm",
        .param = 123456789,
    }, .{
        .name = "fibonacci",
        .filename = "zig-out/lib/fibonacci.wasm",
        .param = 20,
    }, .{
        .name = "mandelbrot",
        .filename = "zig-out/lib/mandelbrot.wasm",
        .param = 20,
    } };

    for (benchmarks) |benchmark| {
        run(allocator, benchmark) catch |e| {
            std.log.err("{s} 'run' invocation failed with error: {}\n", .{ benchmark.name, e });
            return e;
        };
    }
}
