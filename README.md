# Bytebox

<div align="center">
<a href=https://webassembly.org/><img src="https://avatars.githubusercontent.com/u/11578470?s=200&v=4" alt="Markdown Logo" width="150"/></a>

Bytebox is a Webassembly VM.
</div>

## Getting started

### Requirements
Bytebox currently builds with [Zig 0.10.0](https://ziglang.org/download). Other versions have not been tested - use at your discretion.

### Run

```
git clone --recurse-submodules https://github.com/rdunnington/bytebox.git
cd bytebox
zig build test  # run the official WebAssembly spec testsuite
zig build bench # run the benchmarks (not robust)
```

### Usage

You can use the standalone runner to load and execute WebAssembly programs:
```
zig build run -- <wasmfile>
```

Or embed Bytebox in your own programs:

```
# build.zig
const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const exe = b.addExecutable("my_program", "src/main.zig");
    exe.addPackage(std.build.Pkg{
        .name = "bytebox",
        .source = .{ .path = "bytebox/src/core.zig" }, // assumes bytebox is a submodule located in the root dir
    });
    exe.setTarget(b.standardTargetOptions(.{}));
    exe.setBuildMode(b.standardReleaseOptions());
    exe.install();
    const run = exe.run();
    const step = b.step("run", "runs my_program");
    step.dependOn(&run.step);
}

# main.zig
const std = @import("std");
const bytebox = @import("bytebox");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator: std.mem.Allocator = gpa.allocator();

    var wasm_data: []u8 = try std.fs.cwd().readFileAlloc(allocator, "example.wasm", 1024 * 128);
    defer allocator.free(wasm_data);

    var module_definition = bytebox.ModuleDefinition.init(allocator);
    try module_definition.decode(wasm_data);
    defer module_definition.deinit();

    var module_instance = bytebox.ModuleInstance.init(&module_definition, allocator);
    try module_instance.instantiate(.{});
    defer module_instance.deinit();
}
```

## Status

[WebAssembly](https://webassembly.github.io/spec/core/index.html) support:

| Status | Feature |
| --- | --- |
|✔|WebAssembly 1.0|
|✔|Sign extension instructions|
|✔|Non-trapping float-to-int conversion|
|✔|Multiple values|
|✔|Reference types|
|✔|Table instructions|
|✔|Multiple tables|
|✔|Bulk memory and table instructions|
|❌|Vector instructions|

### Future
This project is still a work in progress. Plans for further development include:
* Vector instructions
* API ergonomics
* Optimization
* WASI
