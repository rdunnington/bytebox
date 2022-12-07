const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});

    hookExeWithStep(b, target, "wasmtest", "test.zig", "test", "Run the test suite");
    hookExeWithStep(b, target, "host", "main.zig", "run", "Run a wasm program");
}

fn hookExeWithStep(b: *std.build.Builder, target: anytype, exe_name: []const u8, root_src: []const u8, step_name: []const u8, description: []const u8) void {
    const exe = b.addExecutable(exe_name, root_src);

    if (builtin.os.tag == .windows) {
        exe.addLibraryPath("C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.19041.0\\um\\x64");
        exe.linkSystemLibrary("kernel32");
    }

    const mode = b.standardReleaseOptions();

    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const run = exe.run();
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run.addArgs(args);
    }

    const step = b.step(step_name, description);
    step.dependOn(&run.step);
}
