// 0.12.0: zig build-exe memtest.zig -target wasm64-freestanding -fno-entry --export=memtest -O ReleaseSmall
// 0.11.0: zig build-lib memtest.zig -target wasm64-freestanding -dynamic -rdynamic -O ReleaseSmall

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

const PAGE_SIZE = 64 * KB;
const PAGES_PER_GB = GB / PAGE_SIZE;

export fn memtest() i32 {
    _ = @wasmMemoryGrow(0, PAGES_PER_GB * 4);

    var mem: [*]u8 = @ptrFromInt(4 * GB);

    for (0..MB) |i| {
        mem[i] = 0xFF;
        mem[(4 * GB) - MB + i] = 0xFF;
    }
    return 0;
}

// export fn memtest() void {
//     _ = @wasmMemoryGrow(0, PAGES_PER_GB * 8);
// }
