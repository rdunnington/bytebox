const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");

const Val = core.Val;
const ValType = core.ValType;
const ModuleInstance = core.ModuleInstance;
const ModuleImports = core.ModuleImports;

// Values taken from https://github.com/AssemblyScript/wasi-shim/blob/main/assembly/bindings/
const Errno = enum(u8) {
    SUCCESS = 0, // No error occurred. System call completed successfully.
    TOOBIG = 1, // Argument list too long.
    ACCES = 2, // Permission denied.
    ADDRINUSE = 3, // Address in use.
    ADDRNOTAVAIL = 4, // Address not available.
    AFNOSUPPORT = 5, // Address family not supported.
    AGAIN = 6, // Resource unavailable, or operation would block.
    ALREADY = 7, // Connection already in progress.
    BADF = 8, // Bad file descriptor.
    BADMSG = 9, // Bad message.
    BUSY = 10, // Device or resource busy.
    CANCELED = 11, // Operation canceled.
    CHILD = 12, // No child processes.
    CONNABORTED = 13, // Connection aborted.
    CONNREFUSED = 14, // Connection refused.
    CONNRESET = 15, // Connection reset.
    DEADLK = 16, // Resource deadlock would occur.
    DESTADDRREQ = 17, // Destination address required.
    DOM = 18, // Mathematics argument out of domain of function.
    DQUOT = 19, // Reserved.
    EXIST = 20, // File exists.
    FAULT = 21, // Bad address.
    FBIG = 22, // File too large.
    HOSTUNREACH = 23, // Host is unreachable.
    IDRM = 24, // Identifier removed.
    ILSEQ = 25, // Illegal byte sequence.
    INPROGRESS = 26, // Operation in progress.
    INTR = 27, // Interrupted function.
    INVAL = 28, // Invalid argument.
    IO = 29, // I/O error.
    ISCONN = 30, // Socket is connected.
    ISDIR = 31, // Is a directory.
    LOOP = 32, // Too many levels of symbolic links.
    MFILE = 33, // File descriptor value too large.
    MLINK = 34, // Too many links.
    MSGSIZE = 35, // Message too large.
    MULTIHOP = 36, // Reserved.
    NAMETOOLONG = 37, // Filename too long.
    NETDOWN = 38, // Network is down.
    NETRESET = 39, // Connection aborted by network.
    NETUNREACH = 40, // Network unreachable.
    NFILE = 41, // Too many files open in system.
    NOBUFS = 42, // No buffer space available.
    NODEV = 43, // No such device.
    NOENT = 44, // No such file or directory.
    NOEXEC = 45, // Executable file format error.
    NOLCK = 46, // No locks available.
    NOLINK = 47, // Reserved.
    NOMEM = 48, // Not enough space.
    NOMSG = 49, // No message of the desired type.
    NOPROTOOPT = 50, // Protocol not available.
    NOSPC = 51, // No space left on device.
    NOSYS = 52, // Function not supported.
    NOTCONN = 53, // The socket is not connected.
    NOTDIR = 54, // Not a directory or a symbolic link to a directory.
    NOTEMPTY = 55, // Directory not empty.
    NOTRECOVERABLE = 56, // State not recoverable.
    NOTSOCK = 57, // Not a socket.
    NOTSUP = 58, // Not supported, or operation not supported on socket.
    NOTTY = 59, // Inappropriate I/O control operation.
    NXIO = 60, // No such device or address.
    OVERFLOW = 61, // Value too large to be stored in data type.
    OWNERDEAD = 62, // Previous owner died.
    PERM = 63, // Operation not permitted.
    PIPE = 64, // Broken pipe.
    PROTO = 65, // Protocol error.
    PROTONOSUPPORT = 66, // Protocol not supported.
    PROTOTYPE = 67, // Protocol wrong type for socket.
    RANGE = 68, // Result too large.
    ROFS = 69, // Read-only file system.
    SPIPE = 70, // Invalid seek.
    SRCH = 71, // No such process.
    STALE = 72, // Reserved.
    TIMEDOUT = 73, // Connection timed out.
    TXTBSY = 74, // Text file busy.
    XDEV = 75, // Cross-device link.
    NOTCAPABLE = 76, // Extension: Capabilities insufficient.

    fn translateError(err: anyerror) Errno {
        return switch (err) {
            error.OutOfMemory => .NOMEM,
            else => .INVAL,
        };
    }
};

const Helpers = struct {
    fn strings_sizes_get(module: *ModuleInstance, strings: [][]const u8, params: []const Val, returns: []Val) void {
        std.debug.assert(params.len == 2);
        std.debug.assert(std.meta.activeTag(params[0]) == .I32);
        std.debug.assert(std.meta.activeTag(params[1]) == .I32);
        std.debug.assert(returns.len == 1);

        const strings_count: u32 = @intCast(u32, strings.len);
        var strings_length: u32 = 0;
        for (strings) |string| {
            strings_length += @intCast(u32, string.len) + 1; // +1 for required null terminator of each string
        }

        const dest_string_count = @bitCast(u32, params[0].I32);
        const dest_string_length = @bitCast(u32, params[1].I32);

        module.memoryWriteInt(u32, strings_count, dest_string_count);
        module.memoryWriteInt(u32, strings_length, dest_string_length);

        returns[0] = Val{ .I32 = @enumToInt(Errno.SUCCESS) };
    }

    fn strings_get(module: *ModuleInstance, strings: [][]const u8, params: []const Val, returns: []Val) void {
        std.debug.assert(params.len == 2);
        std.debug.assert(std.meta.activeTag(params[0]) == .I32);
        std.debug.assert(std.meta.activeTag(params[1]) == .I32);
        std.debug.assert(returns.len == 1);

        const dest_string_ptrs_begin = @bitCast(u32, params[0].I32);
        const dest_string_mem_begin = @bitCast(u32, params[1].I32);

        var dest_string_ptrs: u32 = dest_string_ptrs_begin;
        var dest_string_strings: u32 = dest_string_mem_begin;

        for (strings) |string| {
            module.memoryWriteInt(u32, dest_string_strings, dest_string_ptrs);

            var mem: []u8 = module.memorySlice(dest_string_strings, string.len + 1);
            std.mem.copy(u8, mem[0..string.len], string);
            mem[string.len] = 0; // null terminator

            dest_string_ptrs += @sizeOf(u32);
            dest_string_strings += @intCast(u32, string.len + 1);
        }

        returns[0] = Val{ .I32 = @enumToInt(Errno.SUCCESS) };
    }
};

fn wasi_proc_exit(_: ?*anyopaque, _: *ModuleInstance, params: []const Val, returns: []Val) void {
    std.debug.assert(params.len == 1);
    std.debug.assert(std.meta.activeTag(params[0]) == .I32);
    std.debug.assert(returns.len == 0);

    var exit_code: u8 = @truncate(u8, @bitCast(u32, params[0].I32));
    std.os.exit(exit_code);
}

fn wasi_args_sizes_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    Helpers.strings_sizes_get(module, module.argv, params, returns);
}

fn wasi_args_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    Helpers.strings_get(module, module.argv, params, returns);
}

fn wasi_environ_sizes_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    Helpers.strings_sizes_get(module, module.env, params, returns);
}

fn wasi_environ_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    Helpers.strings_get(module, module.env, params, returns);
}

fn wasi_fd_write(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    std.debug.assert(params.len == 4);
    std.debug.assert(std.meta.activeTag(params[0]) == .I32);
    std.debug.assert(std.meta.activeTag(params[1]) == .I32);
    std.debug.assert(std.meta.activeTag(params[2]) == .I32);
    std.debug.assert(std.meta.activeTag(params[3]) == .I32);
    std.debug.assert(returns.len == 1);

    const fd_raw = @bitCast(u32, params[0].I32);
    const iovec_array_begin = @bitCast(u32, params[1].I32);
    const iovec_array_count = @bitCast(u32, params[2].I32);
    const bytes_written_offset = @bitCast(u32, params[3].I32);

    const fd: std.os.fd_t = switch (fd_raw) {
        0 => std.io.getStdIn().handle,
        1 => std.io.getStdOut().handle,
        2 => std.io.getStdErr().handle,
        else => unreachable, // TODO handle this
    };

    var stack_iov = [_]std.os.iovec_const{undefined} ** 32;
    if (stack_iov.len < iovec_array_count) {
        unreachable; // TODO handle this
    }

    // std.debug.print("fd_raw: {}, iovec_array_begin: {}, iovec_array_count: {}, bytes_written_offset: {}\n", .{fd_raw,
    //     iovec_array_begin,
    //     iovec_array_count,
    //     bytes_written_offset,});

    var errno = Errno.SUCCESS;

    const iov = stack_iov[0..iovec_array_count];
    {
        const iovec_array_bytes_length = @sizeOf(u32) * 2 * iovec_array_count;
        const iovec_mem: []const u8 = module.memorySlice(iovec_array_begin, iovec_array_bytes_length);
        var stream = std.io.fixedBufferStream(iovec_mem);
        var reader = stream.reader();

        for (iov) |*vec| {
            const iov_base: u32 = reader.readIntLittle(u32) catch {
                errno = Errno.INVAL;
                // std.debug.print("fail reading iov_base\n" , .{});
                break;
            };
            const iov_len: u32 = reader.readIntLittle(u32) catch {
                errno = Errno.INVAL;
                // std.debug.print("fail reading iov_len\n", .{});
                break;
            };
            // std.debug.print("iov_base: {}, iov_len: {}\n", .{iov_base, iov_len});
            const mem: []const u8 = module.memorySlice(iov_base, iov_len);
            // std.debug.print("iovec mem: {s}\n", .{mem});

            vec.iov_base = mem.ptr;
            vec.iov_len = mem.len;
        }
    }

    if (errno == Errno.SUCCESS) {
        if (std.os.writev(fd, iov)) |written_bytes| {
            module.memoryWriteInt(u32, @intCast(u32, written_bytes), bytes_written_offset);
        } else |err| {
            errno = Errno.translateError(err);
            // std.debug.print("fail writev\n", .{});
        }
    }

    // std.debug.print("errno: {}\n", .{errno});

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

pub fn wasi_random_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    std.debug.assert(params.len == 2);
    std.debug.assert(std.meta.activeTag(params[0]) == .I32);
    std.debug.assert(std.meta.activeTag(params[1]) == .I32);
    std.debug.assert(returns.len == 1);

    const array_begin_offset: u32 = @bitCast(u32, params[0].I32);
    const array_length: u32 = @bitCast(u32, params[1].I32);

    var errno = Errno.SUCCESS;

    if (array_length > 0) {
        var mem: []u8 = module.memorySlice(array_begin_offset, array_length);
        std.crypto.random.bytes(mem);
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

pub fn makeImports(allocator: std.mem.Allocator) !ModuleImports {
    var imports: ModuleImports = try ModuleImports.init("wasi_snapshot_preview1", null, allocator);

    const void_returns = &[0]ValType{};

    try imports.addHostFunction("args_sizes_get", null, &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_args_sizes_get);
    try imports.addHostFunction("args_get", null, &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_args_get);
    try imports.addHostFunction("environ_sizes_get", null, &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_environ_sizes_get);
    try imports.addHostFunction("environ_get", null, &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_environ_get);
    try imports.addHostFunction("fd_write", null, &[_]ValType{ .I32, .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_write);
    try imports.addHostFunction("random_get", null, &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_random_get);
    try imports.addHostFunction("proc_exit", null, &[_]ValType{.I32}, void_returns, wasi_proc_exit);

    return imports;
}
