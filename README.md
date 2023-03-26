# Bytebox

<div align="center">
<a href=https://webassembly.org/><img src="https://avatars.githubusercontent.com/u/11578470?s=200&v=4" alt="Markdown Logo" width="150"/></a>

Bytebox is a Webassembly VM.
</div>

## Getting started

### Requirements
Bytebox currently builds with [Zig 0.10.0](https://ziglang.org/download). Other versions have not been tested - use at your discretion.

### Run

```sh
git clone --recurse-submodules https://github.com/rdunnington/bytebox.git
cd bytebox
zig build test  # run the official WebAssembly spec testsuite
zig build bench # run the benchmarks (not robust)
```

### Usage

You can use the standalone runtime to load and execute WebAssembly programs:
```sh
zig build run -- <file> [function] [function args]...
```

Or embed Bytebox in your own programs:

```zig
// build.zig
const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const exe = b.addExecutable("my_program", "src/main.zig");
    exe.addPackage(std.build.Pkg{
        .name = "bytebox",
        .source = .{ .path = "bytebox/src/core.zig" }, // submodule in the root dir
    });
    exe.setTarget(b.standardTargetOptions(.{}));
    exe.setBuildMode(b.standardReleaseOptions());
    exe.install();
    const run = exe.run();
    const step = b.step("run", "runs my_program");
    step.dependOn(&run.step);
}

// main.zig
const std = @import("std");
const bytebox = @import("bytebox");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator: std.mem.Allocator = gpa.allocator();

    var wasm_data: []u8 = try std.fs.cwd().readFileAlloc(allocator, "example.wasm", 1024 * 128);
    defer allocator.free(wasm_data);

    var module_definition = bytebox.ModuleDefinition.init(allocator, .{});
    defer module_definition.deinit();
    try module_definition.decode(wasm_data);

    var module_instance = bytebox.ModuleInstance.init(&module_definition, allocator);
    defer module_instance.deinit();
    try module_instance.instantiate(.{});
}
```

A C API wrapper is planned for easier integration with other languages.

## Status

This project is still in development. However, usage of the library and standalone runtime 

| Legend | Meaning |
| --- | --- |
|✅|Implemented|
|❌|TODO|
|💀|Removed from spec|

### [WebAssembly](https://webassembly.github.io/spec/core/index.html) support:

| Status | Feature |
| --- | --- |
|✅|WebAssembly 1.0|
|✅|Sign extension instructions|
|✅|Non-trapping float-to-int conversion|
|✅|Multiple values|
|✅|Reference types|
|✅|Table instructions|
|✅|Multiple tables|
|✅|Bulk memory and table instructions|
|❌|Vector instructions|

### [WASI Preview 1](https://github.com/WebAssembly/WASI/tree/main) support:

| Status | Feature |
| --- | --- |
|✅|args_get|
|✅|args_sizes_get|
|✅|environ_get|
|✅|environ_sizes_get|
|✅|clock_res_get|
|✅|clock_time_get|
|✅|fd_advise|
|✅|fd_allocate|
|✅|fd_close|
|❌|fd_datasync|
|✅|fd_fdstat_get|
|✅|fd_fdstat_set_flags|
|💀|fd_fdstat_set_rights|
|✅|fd_filestat_get|
|✅|fd_filestat_set_size|
|✅|fd_filestat_set_times|
|✅|fd_pread|
|✅|fd_prestat_get|
|✅|fd_prestat_dir_name|
|✅|fd_pwrite|
|✅|fd_read|
|✅|fd_readdir|
|✅|fd_renumber|
|✅|fd_seek|
|❌|fd_sync|
|✅|fd_tell|
|✅|fd_write|
|✅|path_create_directory|
|✅|path_filestat_get|
|✅|path_filestat_set_times|
|❌|path_link|
|✅|path_open|
|❌|path_readlink|
|✅|path_remove_directory|
|❌|path_rename|
|✅|path_symlink|
|✅|path_unlink_file|
|❌|poll_oneoff|
|✅|proc_exit|
|💀|proc_raise|
|❌|sched_yield|
|✅|random_get|
|❌|sock_accept|
|❌|sock_recv|
|❌|sock_send|
|❌|sock_shutdown|

### Roadmap
These tasks must be completed to enter alpha:
* WASI support on all platforms
* Vector instructions
* API ergonomics pass
* Documentation
* General TODO/code cleanup
* Crash hardening/fuzzing

To enter beta:
* No breaking API changes after this point
* Performance competitive with other well-known interpreters (e.g. [micro-wasm-runtime](https://github.com/bytecodealliance/wasm-micro-runtime), [wasm3](https://github.com/wasm3/wasm3))

To have a 1.0 release:
* Tested with a wide variety of wasm programs
* Successfully used in other beta-quality projects
