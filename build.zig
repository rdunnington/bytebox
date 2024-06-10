const std = @import("std");

const Build = std.Build;
const Module = Build.Module;
const ModuleImport = Module.Import;
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

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const stable_array = b.dependency("zig-stable-array", .{
        .target = target,
        .optimize = optimize,
    });

    var bench_add_one_step: *CompileStep = buildWasmExe(b, "bench/samples/add-one.zig", .Wasm32);
    var bench_fibonacci_step: *CompileStep = buildWasmExe(b, "bench/samples/fibonacci.zig", .Wasm32);
    var bench_mandelbrot_step: *CompileStep = buildWasmExe(b, "bench/samples/mandelbrot.zig", .Wasm32);

    const stable_array_import = ModuleImport{ .name = "stable-array", .module = stable_array.module("zig-stable-array") };

    const bytebox_module: *Build.Module = b.addModule("bytebox", .{
        .root_source_file = b.path("src/core.zig"),
        .imports = &[_]ModuleImport{stable_array_import},
    });

    // exe.root_module.addImport(import.name, import.module);

    const imports = [_]ModuleImport{
        .{ .name = "bytebox", .module = bytebox_module },
        .{ .name = "stable-array", .module = stable_array.module("zig-stable-array") },
    };

    _ = buildExeWithRunStep(b, target, optimize, &imports, .{
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
    _ = buildExeWithRunStep(b, target, optimize, &imports, .{
        .exe_name = "bench",
        .root_src = "bench/main.zig",
        .step_name = "bench",
        .description = "Run the benchmark suite",
        .step_dependencies = &bench_steps,
    });

    const lib_bytebox: *Build.Step.Compile = b.addStaticLibrary(.{
        .name = "bytebox",
        .root_source_file = b.path("src/cffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_bytebox.root_module.addImport(stable_array_import.name, stable_array_import.module);
    lib_bytebox.installHeader(b.path("src/bytebox.h"), "bytebox.h");
    b.installArtifact(lib_bytebox);

    // Unit tests
    const unit_tests: *Build.Step.Compile = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addImport(stable_array_import.name, stable_array_import.module);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const unit_test_step = b.step("test-unit", "Run unit tests");
    unit_test_step.dependOn(&run_unit_tests.step);

    // wasm tests
    const wasm_testsuite_step = buildExeWithRunStep(b, target, optimize, &imports, .{
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

    // mem64 test
    const compile_mem64_test = buildWasmExe(b, "test/mem64/memtest.zig", .Wasm64);
    b.getInstallStep().dependOn(&compile_mem64_test.step);

    const mem64_test_step: *Build.Step = buildExeWithRunStep(b, target, optimize, &imports, .{
        .exe_name = "test-mem64",
        .root_src = "test/mem64/main.zig",
        .step_name = "test-mem64",
        .description = "Run the mem64 test",
    });

    // All tests
    const all_tests_step = b.step("test", "Run unit, wasm, and wasi tests");
    all_tests_step.dependOn(unit_test_step);
    all_tests_step.dependOn(wasm_testsuite_step);
    all_tests_step.dependOn(wasi_testsuite_step);
    all_tests_step.dependOn(mem64_test_step);
}

fn buildExeWithRunStep(b: *Build, target: Build.ResolvedTarget, optimize: std.builtin.Mode, imports: []const ModuleImport, opts: ExeOpts) *Build.Step {
    const exe: *Build.Step.Compile = b.addExecutable(.{
        .name = opts.exe_name,
        .root_source_file = b.path(opts.root_src),
        .target = target,
        .optimize = optimize,
    });

    for (imports) |import| {
        exe.root_module.addImport(import.name, import.module);
    }

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

const WasmArch = enum {
    Wasm32,
    Wasm64,
};

fn buildWasmExe(b: *Build, filepath: []const u8, arch: WasmArch) *CompileStep {
    var filename: []const u8 = std.fs.path.basename(filepath);
    const filename_no_extension: []const u8 = filename[0 .. filename.len - 4];

    const cpu_arch: std.Target.Cpu.Arch = if (arch == .Wasm32) .wasm32 else .wasm64;

    var target_query: std.Target.Query = .{
        .cpu_arch = cpu_arch,
        .os_tag = .freestanding,
    };
    target_query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.bulk_memory));
    target_query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.nontrapping_fptoint));
    target_query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.multivalue));
    target_query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.mutable_globals));
    target_query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.reference_types));
    target_query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.sign_ext));
    target_query.cpu_features_add.addFeature(@intFromEnum(std.Target.wasm.Feature.simd128));

    var exe = b.addExecutable(.{
        .name = filename_no_extension,
        .root_source_file = b.path(filepath),
        .target = b.resolveTargetQuery(target_query),
        .optimize = .ReleaseSmall,
    });
    exe.rdynamic = true;
    exe.entry = .disabled;

    b.installArtifact(exe);

    return exe;
}
