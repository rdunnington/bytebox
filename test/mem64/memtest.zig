const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

const PAGE_SIZE = 64 * KB;
const PAGES_PER_GB = GB / PAGE_SIZE;

fn assert(cond: bool) !void {
    if (!cond) {
        return error.Failed;
    }
}

export fn memtest(val_i32: i32, val_i64: i64, val_f32: f32, val_f64: f64) i32 {
    testInternal(val_i32, val_i64, val_f32, val_f64) catch {
        return 1;
    };
    return 0;
}

fn testInternal(val_i32: i32, val_i64: i64, val_f32: f32, val_f64: f64) !void {
    _ = @wasmMemoryGrow(0, PAGES_PER_GB * 4);

    const grow_value: isize = @wasmMemoryGrow(0, PAGES_PER_GB * 6); // memory.grow
    try assert(grow_value != -1);
    const start_page: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(grow_value)));

    const mem = start_page + (GB * 4);
    const mem_stores = mem + MB * 1; // volatile?
    const mem_loads = mem + MB * 2; // volatile?

    const num_pages: usize = @wasmMemorySize(0);
    try assert(num_pages >= PAGES_PER_GB * 6);

    const ptr_load_i32 = @as(*volatile i32, @ptrCast(@alignCast(mem_loads)));
    const ptr_load_i64 = @as(*volatile i64, @ptrCast(@alignCast(mem_loads + 8)));
    const ptr_load_f32 = @as(*volatile f32, @ptrCast(@alignCast(mem_loads + 16)));
    const ptr_load_f64 = @as(*volatile f64, @ptrCast(@alignCast(mem_loads + 24)));

    ptr_load_i32.* = val_i32; // i32.store
    ptr_load_i64.* = val_i64; // i64.store
    ptr_load_f32.* = val_f32; // f32.store
    ptr_load_f64.* = val_f64; // f64.store

    try assert(ptr_load_i32.* == val_i32);
    try assert(ptr_load_i64.* == val_i64);
    try assert(ptr_load_f32.* == val_f32);
    try assert(ptr_load_f64.* == val_f64);

    const ptr_store_i32 = @as(*volatile i32, @ptrCast(@alignCast(mem_stores)));
    const ptr_store_i64 = @as(*volatile i64, @ptrCast(@alignCast(mem_stores + 8)));
    const ptr_store_f32 = @as(*volatile f32, @ptrCast(@alignCast(mem_stores + 16)));
    const ptr_store_f64 = @as(*volatile f64, @ptrCast(@alignCast(mem_stores + 24)));

    ptr_store_i32.* = ptr_load_i32.*; // i32.load && i32.store
    ptr_store_i64.* = ptr_load_i64.*; // i64.load && i64.store
    ptr_store_f32.* = ptr_load_f32.*; // f32.load && f32.store
    ptr_store_f64.* = ptr_load_f64.*; // f64.load && f64.store

    try assert(ptr_store_i32.* == ptr_load_i32.*);
    try assert(ptr_store_i64.* == ptr_load_i64.*);
    try assert(ptr_store_f32.* == ptr_load_f32.*);
    try assert(ptr_store_f64.* == ptr_load_f64.*);

    var load32: i32 = 0;
    ptr_load_i32.* = 0x7F;
    load32 = @as(*volatile i8, @ptrCast(@alignCast(ptr_load_i32))).*; // i32.load8_s
    try assert(load32 == 0x7F);
    ptr_load_i32.* = 0xFF;
    load32 = @as(*volatile u8, @ptrCast(@alignCast(ptr_load_i32))).*; // i32.load8_u
    try assert(load32 == 0xFF);
    ptr_load_i32.* = 0x7FFF;
    load32 = @as(*volatile i16, @ptrCast(@alignCast(ptr_load_i32))).*; // i32.load16_s
    try assert(load32 == 0x7FFF);
    ptr_load_i32.* = 0xFFFF;
    load32 = @as(*volatile u16, @ptrCast(@alignCast(ptr_load_i32))).*; // i32.load16_s
    try assert(load32 == 0xFFFF);

    var load64: i64 = 0;
    ptr_load_i64.* = 0x7F;
    load64 = @as(*volatile i8, @ptrCast(@alignCast(ptr_load_i64))).*; // i64.load8_s
    try assert(load64 == 0x7F);
    ptr_load_i64.* = 0xFF;
    load64 = @as(*volatile u8, @ptrCast(@alignCast(ptr_load_i64))).*; // i64.load8_u
    try assert(load64 == 0xFF);
    ptr_load_i64.* = 0x7FFF;
    load64 = @as(*volatile i16, @ptrCast(@alignCast(ptr_load_i64))).*; // i64.load16_s
    try assert(load64 == 0x7FFF);
    ptr_load_i64.* = 0xFFFF;
    load64 = @as(*volatile u16, @ptrCast(@alignCast(ptr_load_i64))).*; // i64.load16_s
    try assert(load64 == 0xFFFF);
    ptr_load_i64.* = 0x7FFFFFFF;
    load64 = @as(*volatile i32, @ptrCast(@alignCast(ptr_load_i64))).*; // i64.load32_s
    try assert(load64 == 0x7FFFFFFF);
    ptr_load_i64.* = 0xFFFFFFFF;
    load64 = @as(*volatile u32, @ptrCast(@alignCast(ptr_load_i64))).*; // i64.load32_s
    try assert(load64 == 0xFFFFFFFF);

    const memset_dest = (mem + KB)[0..KB];
    const memcpy_dest = (mem + KB * 2)[0..KB];
    @memset(memset_dest, 0xFF); // memory.fill
    @memcpy(memcpy_dest, memset_dest); // memory.copy

    try assert(memset_dest[0] == 0xFF);
    try assert(memset_dest[KB - 1] == 0xFF);
    try assert(memcpy_dest[0] == 0xFF);
    try assert(memcpy_dest[KB - 1] == 0xFF);
}
