const std = @import("std");
const builtin = @import("builtin");

const CrossTarget = std.zig.CrossTarget;
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;
const LibExeObjStep = std.build.LibExeObjStep;

const ExeOpts = struct {
    exe_name: []const u8,
    root_src: []const u8,
    step_name: []const u8,
    description: []const u8,
    needs_root_package: bool = false,
    step_dependencies: ?[]*std.build.Step = null,
};

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});

    var bench_fibonacci_step: *LibExeObjStep = buildWasmLib(b, "bench/samples/fibonacci.zig");
    var bench_mandelbrot_step: *LibExeObjStep = buildWasmLib(b, "bench/samples/mandelbrot.zig");

    hookExeWithStep(b, target, .{
        .exe_name = "host",
        .root_src = "src/main.zig",
        .step_name = "run",
        .description = "Run a wasm program",
    });
    hookExeWithStep(b, target, .{
        .exe_name = "testsuite",
        .root_src = "test/testsuite.zig",
        .step_name = "test",
        .description = "Run the test suite",
        .needs_root_package = true,
    });
    hookExeWithStep(b, target, .{
        .exe_name = "benchmark",
        .root_src = "bench/benchmark.zig",
        .step_name = "bench",
        .description = "Run the benchmark suite",
        .needs_root_package = true,
        .step_dependencies = &[_]*std.build.Step{
            &bench_fibonacci_step.step,
            &bench_mandelbrot_step.step,
        },
    });
}

fn hookExeWithStep(b: *Builder, target: CrossTarget, opts: ExeOpts) void {
    const exe = b.addExecutable(opts.exe_name, opts.root_src);

    if (builtin.os.tag == .windows) {
        exe.addLibraryPath("C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.19041.0\\um\\x64");
        exe.linkSystemLibrary("kernel32");
    }

    const pkg_stable_array = Pkg{
        .name = "stable-array",
        .source = .{ .path = "zig-stable-array/stable_array.zig" },
    };

    exe.addPackage(pkg_stable_array);
    if (opts.needs_root_package) {
        const root_pkg = Pkg{
            .name = "wasm",
            .source = .{ .path = "src/vm.zig" },
            .dependencies = &[_]Pkg{pkg_stable_array},
        };
        exe.addPackage(root_pkg);
    }

    const mode = b.standardReleaseOptions();

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
