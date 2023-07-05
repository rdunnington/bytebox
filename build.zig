const std = @import("std");

const CrossTarget = std.zig.CrossTarget;
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;

const ExeOpts = struct {
    exe_name: []const u8,
    root_src: []const u8,
    step_name: []const u8,
    description: []const u8,
    step_dependencies: ?[]*std.build.Step = null,
    should_emit_asm: bool = false,
};

pub fn build(b: *Builder) void {
    const should_emit_asm = b.option(bool, "asm", "Emit asm for the bytebox binaries") orelse false;

    const target = b.standardTargetOptions(.{});

    var bench_add_one_step: *LibExeObjStep = buildWasmLib(b, "bench/samples/add-one.zig");
    var bench_fibonacci_step: *LibExeObjStep = buildWasmLib(b, "bench/samples/fibonacci.zig");
    var bench_mandelbrot_step: *LibExeObjStep = buildWasmLib(b, "bench/samples/mandelbrot.zig");

    buildExeWithStep(b, target, .{
        .exe_name = "bytebox",
        .root_src = "run/main.zig",
        .step_name = "run",
        .description = "Run a wasm program",
        .should_emit_asm = should_emit_asm,
    });
    buildExeWithStep(b, target, .{
        .exe_name = "testsuite",
        .root_src = "test/main.zig",
        .step_name = "test",
        .description = "Run the test suite",
    });
    buildExeWithStep(b, target, .{
        .exe_name = "benchmark",
        .root_src = "bench/main.zig",
        .step_name = "bench",
        .description = "Run the benchmark suite",
        .step_dependencies = &[_]*std.build.Step{
            &bench_add_one_step.step,
            &bench_fibonacci_step.step,
            &bench_mandelbrot_step.step,
        },
    });

    var c_header = b.addInstallFileWithDir(std.build.FileSource{ .path = "src/bytebox.h" }, .header, "bytebox.h");

    const lib_bytebox = b.addStaticLibrary("bytebox", "src/cffi.zig");
    lib_bytebox.setTarget(target);
    lib_bytebox.setBuildMode(b.standardReleaseOptions());
    lib_bytebox.step.dependOn(&c_header.step);
    lib_bytebox.emit_asm = if (should_emit_asm) .emit else .default;
    // const lib_bytebox = b.addStaticLibrary(.{
    //     .name = "bytebox",
    //     .root_source_file = .{ .path = "src/cffi.zig" },
    //     .target = target,
    //     .optimize = optimize,
    // });
    // lib_bytebox.installHeader("src/bytebox.h", "bytebox.h");

    lib_bytebox.install();
}

fn buildExeWithStep(b: *Builder, target: CrossTarget, opts: ExeOpts) void {
    const exe = b.addExecutable(opts.exe_name, opts.root_src);

    exe.addPackage(std.build.Pkg{
        .name = "bytebox",
        .source = .{ .path = "src/core.zig" },
    });

    const mode = b.standardReleaseOptions();

    exe.emit_asm = if (opts.should_emit_asm) .emit else .default;
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    if (opts.step_dependencies) |steps| {
        for (steps) |step| {
            exe.step.dependOn(step);
        }
    }

    const run = exe.run();
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run.addArgs(args);
    }

    const step = b.step(opts.step_name, opts.description);
    step.dependOn(&run.step);
}

fn buildWasmLib(b: *Builder, filepath: []const u8) *LibExeObjStep {
    var filename: []const u8 = std.fs.path.basename(filepath);
    var filename_no_extension: []const u8 = filename[0 .. filename.len - 4];

    const lib = b.addSharedLibrary(filename_no_extension, filepath, .unversioned);

    const mode = b.standardReleaseOptions();
    lib.setTarget(CrossTarget{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });
    lib.setBuildMode(mode);
    lib.install();

    return lib;
}
