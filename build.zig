const std = @import("std");

const Build = std.Build;
const CrossTarget = std.zig.CrossTarget;
const CompileStep = std.Build.Step.Compile;

const ExeOpts = struct {
    exe_name: []const u8,
    root_src: []const u8,
    step_name: []const u8,
    description: []const u8,
    step_dependencies: ?[]*Build.Step = null,
    should_emit_asm: bool = false,
};

pub fn build(b: *Build) void {
    const should_emit_asm = b.option(bool, "asm", "Emit asm for the bytebox binaries") orelse false;
    const no_clang = b.option(bool, "noclang", "Pass this if clang isn't in the PATH") orelse false;

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    var bench_add_one_step: *CompileStep = buildWasmExe(b, "bench/samples/add-one.zig");
    var bench_fibonacci_step: *CompileStep = buildWasmExe(b, "bench/samples/fibonacci.zig");
    var bench_mandelbrot_step: *CompileStep = buildWasmExe(b, "bench/samples/mandelbrot.zig");

    const bytebox_module: *Build.Module = b.addModule("bytebox", .{
        .root_source_file = b.path("src/core.zig"),
    });

    _ = buildExeWithRunStep(b, target, optimize, bytebox_module, .{
        .exe_name = "bytebox",
        .root_src = "run/main.zig",
        .step_name = "run",
        .description = "Run a wasm program",
        .should_emit_asm = should_emit_asm,
    });

    var bench_steps = [_]*Build.Step{
        &bench_add_one_step.step,
        &bench_fibonacci_step.step,
        &bench_mandelbrot_step.step,
    };
    _ = buildExeWithRunStep(b, target, optimize, bytebox_module, .{
        .exe_name = "bench",
        .root_src = "bench/main.zig",
        .step_name = "bench",
        .description = "Run the benchmark suite",
        .step_dependencies = &bench_steps,
    });

    const lib_bytebox = b.addStaticLibrary(.{
        .name = "bytebox",
        .root_source_file = b.path("src/cffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_bytebox.installHeader(b.path("src/bytebox.h"), "bytebox.h");
    b.installArtifact(lib_bytebox);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const unit_test_step = b.step("test-unit", "Run unit tests");
    unit_test_step.dependOn(&run_unit_tests.step);

    // wasm tests
    const wasm_testsuite_step = buildExeWithRunStep(b, target, optimize, bytebox_module, .{
        .exe_name = "test-wasm",
        .root_src = "test/wasm/main.zig",
        .step_name = "test-wasm",
        .description = "Run the wasm testsuite",
    });

    // wasi tests
    const wasi_testsuite = b.addSystemCommand(&.{"python3"});
    wasi_testsuite.addArg("test/wasi/run.py");
    const wasi_testsuite_step = b.step("test-wasi", "Run wasi testsuite");
    wasi_testsuite_step.dependOn(&wasi_testsuite.step);

    // mem64 step
    var mem64_test_step: ?*Build.Step = null;
    if (!no_clang) {
        // need to use clang to compile the C test due to https://github.com/ziglang/zig/issues/19942
        // eventually we will ziggify this test
        // ideally this test would go away, but the existing spec tests don't provide very good coverage
        // of the instructions
        const compile_memtest = b.addSystemCommand(&.{"clang"});
        compile_memtest.addArg("--target=wasm64-freestanding");
        compile_memtest.addArg("-mbulk-memory");
        compile_memtest.addArg("-nostdlib");
        compile_memtest.addArg("-O2");
        compile_memtest.addArg("-Wl,--no-entry");
        compile_memtest.addArg("-Wl,--export-dynamic");
        compile_memtest.addArg("-o");
        compile_memtest.addArg("test/mem64/memtest.wasm");
        compile_memtest.addFileArg(b.path("test/mem64/memtest.c"));
        compile_memtest.has_side_effects = true;

        b.getInstallStep().dependOn(&compile_memtest.step);

        mem64_test_step = buildExeWithRunStep(b, target, optimize, bytebox_module, .{
            .exe_name = "test-mem64",
            .root_src = "test/mem64/main.zig",
            .step_name = "test-mem64",
            .description = "Run the mem64 test",
        });
    }

    // All tests
    const all_tests_step = b.step("test", "Run unit, wasm, and wasi tests");
    all_tests_step.dependOn(unit_test_step);
    all_tests_step.dependOn(wasm_testsuite_step);
    all_tests_step.dependOn(wasi_testsuite_step);
    if (mem64_test_step) |step| {
        all_tests_step.dependOn(step);
    }
}

fn buildExeWithRunStep(b: *Build, target: Build.ResolvedTarget, optimize: std.builtin.Mode, bytebox_module: *Build.Module, opts: ExeOpts) *Build.Step {
    const exe = b.addExecutable(.{
        .name = opts.exe_name,
        .root_source_file = b.path(opts.root_src),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("bytebox", bytebox_module);

    // exe.emit_asm = if (opts.should_emit_asm) .emit else .default;
    b.installArtifact(exe);

    if (opts.step_dependencies) |steps| {
        for (steps) |step| {
            exe.step.dependOn(step);
        }
    }

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run.addArgs(args);
    }

    const step: *Build.Step = b.step(opts.step_name, opts.description);
    step.dependOn(&run.step);

    return step;
}

fn buildWasmExe(b: *Build, filepath: []const u8) *CompileStep {
    var filename: []const u8 = std.fs.path.basename(filepath);
    const filename_no_extension: []const u8 = filename[0 .. filename.len - 4];

    var exe = b.addExecutable(.{
        .name = filename_no_extension,
        .root_source_file = b.path(filepath),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseSmall,
    });
    exe.rdynamic = true;
    exe.entry = .disabled;

    b.installArtifact(exe);

    return exe;
}
