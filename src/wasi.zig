const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");

const StringPool = @import("stringpool.zig");

const Val = core.Val;
const ValType = core.ValType;
const ModuleInstance = core.ModuleInstance;
const ModuleImports = core.ModuleImports;

const WasiError = error{PathResolveError};
const WasiInitError = std.mem.Allocator.Error || std.os.OpenError || std.os.GetCwdError || StringPool.PutError || WasiError;

const WasiContext = struct {
    const FdInfo = struct {
        fd: std.os.fd_t,
        path_absolute: []const u8,
    };

    cwd: []const u8,
    argv: [][]const u8 = &[_][]u8{},
    env: [][]const u8 = &[_][]u8{},
    dirs: [][]const u8 = &[_][]u8{},
    fd_table: std.AutoHashMap(u32, FdInfo),
    strings: StringPool,
    next_fd_id: u32 = 3,
    allocator: std.mem.Allocator,

    fn init(opts: *const WasiOpts, allocator: std.mem.Allocator) WasiInitError!WasiContext {
        var context = WasiContext{
            .cwd = "",
            .fd_table = std.AutoHashMap(u32, FdInfo).init(allocator),
            .strings = StringPool.init(std.mem.page_size * 16, allocator),
            .allocator = allocator,
        };

        {
            var cwd_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const cwd: []const u8 = try std.os.getcwd(&cwd_buffer);
            context.cwd = try context.strings.put(cwd);
        }

        if (opts.argv) |argv| {
            context.argv = try context.allocator.dupe([]const u8, argv);
            for (argv) |arg, i| {
                context.argv[i] = try context.strings.put(arg);
            }
        }

        if (opts.env) |env| {
            context.env = try context.allocator.dupe([]const u8, env);
            for (env) |e, i| {
                context.env[i] = try context.strings.put(e);
            }
        }

        if (opts.dirs) |dirs| {
            context.dirs = try context.allocator.dupe([]const u8, dirs);
            for (dirs) |dir, i| {
                context.dirs[i] = context.resolveAndCache(null, dir) catch {
                    return WasiError.PathResolveError;
                };
            }
        }

        const path_stdin = try context.strings.put("stdin");
        const path_stdout = try context.strings.put("stdout");
        const path_stderr = try context.strings.put("stderr");

        try context.fd_table.put(0, FdInfo{ .fd = std.io.getStdIn().handle, .path_absolute = path_stdin });
        try context.fd_table.put(1, FdInfo{ .fd = std.io.getStdOut().handle, .path_absolute = path_stdout });
        try context.fd_table.put(2, FdInfo{ .fd = std.io.getStdErr().handle, .path_absolute = path_stderr });

        for (context.dirs) |dir_path| {
            const fd_dir: ?std.os.fd_t = null;
            const flags: u32 = std.os.O.DIRECTORY | std.os.O.RDWR;
            const mode: std.os.mode_t = 0;
            var unused: Errno = undefined;
            _ = context.fdOpen(fd_dir, dir_path, flags, mode, &unused);
        }

        return context;
    }

    fn deinit(self: *WasiContext) void {
        self.strings.deinit();
        self.fd_table.deinit();
    }

    fn resolveAndCache(self: *WasiContext, fd_dir: ?std.os.fd_t, path: []const u8) ![]const u8 {
        std.debug.assert(path[path.len - 1] != 0);
        if (self.strings.find(path)) |found| {
            return found;
        }

        var static_path_buffer: [std.fs.MAX_PATH_BYTES * 2]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&static_path_buffer);
        const allocator = fba.allocator();

        var path_dir: []const u8 = "";
        if (fd_dir) |fd| {
            var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            path_dir = try std.os.getFdPath(fd, &path_buffer);
        }

        const paths = [_][]const u8{ path_dir, path };

        if (std.fs.path.resolve(allocator, &paths)) |resolved_path| {
            const cached_path: []const u8 = try self.strings.put(resolved_path);
            return cached_path;
        } else |err| {
            std.debug.print("failed to resolve path '{s}', caught {}\n", .{ path, err });
            return err;
        }
    }

    fn fdLookup(self: *const WasiContext, fd_wasi: u32, errno: *Errno) ?*const FdInfo {
        if (fd_wasi != FD_WASI_INVALID) {
            if (self.fd_table.getPtr(fd_wasi)) |info| {
                // std.debug.print("fd_wasi {s} -> info {}\n", .{ info.path_absolute, info.fd });
                return info;
            }
        }

        errno.* = Errno.BADF;
        return null;
    }

    fn fdDirPath(self: *WasiContext, fd_wasi: u32, errno: *Errno) ?[]const u8 {
        if (fd_wasi != FD_WASI_INVALID and fd_wasi >= 3) { // std handles are 0, 1, 2 so they're not valid paths
            if (self.fd_table.get(fd_wasi)) |info| {
                const path_relative = info.path_absolute[self.cwd.len + 1 ..]; // +1 to skip the last path separator
                return path_relative;
            }
        }

        errno.* = Errno.BADF;
        return null;
    }

    fn fdOpen(self: *WasiContext, fd_dir: ?std.os.fd_t, path: []const u8, flags: u32, mode: std.os.mode_t, errno: *Errno) ?u32 {
        if (self.resolveAndCache(fd_dir, path)) |resolved_path| {
            // std.debug.print("fdOpen: fd_dir {?}\n\tpath: '{s}'\n\tresolved: '{s}'\n", .{ fd_dir, path, resolved_path });
            if (std.os.open(resolved_path, flags, mode)) |fd_os| {
                var fd_wasi: u32 = self.next_fd_id;
                self.next_fd_id += 1;

                const info = FdInfo{
                    .fd = fd_os,
                    .path_absolute = resolved_path,
                };

                self.fd_table.put(fd_wasi, info) catch {
                    fd_wasi = FD_WASI_INVALID;
                };

                return fd_wasi;
            } else |err| {
                // std.debug.print("\terr: {}\n", .{err});
                errno.* = Errno.translateError(err);
            }
        } else |err| {
            errno.* = Errno.translateError(err);
        }

        return null;
    }

    fn fdRemove(self: *WasiContext, wasi_fd: u32) ?std.os.fd_t {
        if (self.fd_table.fetchRemove(wasi_fd)) |result| {
            return result.value.fd;
        } else {
            return null;
        }
    }

    fn hasPathAccess(self: *WasiContext, fd_info: *const FdInfo, relative_path: []const u8, errno: *Errno) bool {
        if (self.dirs.len > 0) {
            const paths = [_][]const u8{ fd_info.path_absolute, relative_path };
            if (std.fs.path.resolve(self.allocator, &paths)) |resolved_path| {
                // std.debug.print("checking hasPathAccess for resolved path '{s}'\n", .{resolved_path});
                for (self.dirs) |allowdir| {
                    // can use startsWith to check because all the paths have been passed through resolve() already
                    if (std.mem.startsWith(u8, resolved_path, allowdir)) {
                        return true;
                    }
                }
            } else |err| {
                std.debug.print("Caught error {} resolving path. Was the fixed buffer allocator not big enough?", .{err});
            }
        }

        errno.* = Errno.NOTCAPABLE;
        return false;
    }

    fn fromUserdata(userdata: ?*anyopaque) *WasiContext {
        std.debug.assert(userdata != null);
        return @ptrCast(*WasiContext, @alignCast(8, userdata.?));
    }
};

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
            error.AccessDenied => .ACCES,
            error.FileTooBig => .FBIG,
            error.IsDir => .ISDIR,
            error.SymLinkLoop => .LOOP,
            error.ProcessFdQuotaExceeded => .MFILE,
            error.NameTooLong => .NAMETOOLONG,
            error.SystemFdQuotaExceeded => .NFILE,
            error.NoDevice => .NODEV,
            error.FileNotFound => .NOENT,
            error.SystemResources => .NOMEM,
            error.NoSpaceLeft => .NOSPC,
            error.NotDir => .NOTDIR,
            error.PathAlreadyExists => .EXIST,
            error.DeviceBusy => .BUSY,
            error.FileLocksNotSupported => .NOTSUP,
            error.WouldBlock => .AGAIN,
            error.FileBusy => .TXTBSY,
            error.Unseekable => .SPIPE,
            error.DirNotEmpty => .NOTEMPTY,
            error.InputOutput => .IO,
            error.DiskQuota => .DQUOT,
            else => .INVAL,
        };
    }
};

const WasiLookupFlags = packed struct {
    symlink_follow: bool,
};

const WasiOpenFlags = packed struct {
    creat: bool,
    directory: bool,
    excl: bool,
    trunc: bool,
};

const WasiRights = packed struct {
    fd_datasync: bool,
    fd_read: bool,
    fd_seek: bool,
    fd_fdstat_set_flags: bool,
    fd_sync: bool,
    fd_tell: bool,
    fd_write: bool,
    fd_advise: bool,
    fd_allocate: bool,
    path_create_directory: bool,
    path_create_file: bool,
    path_link_source: bool,
    path_link_target: bool,
    path_open: bool,
    fd_readdir: bool,
    path_readlink: bool,
    path_rename_source: bool,
    path_rename_target: bool,
    path_filestat_get: bool,
    path_filestat_set_size: bool,
    path_filestat_set_times: bool,
    fd_filestat_get: bool,
    fd_filestat_set_size: bool,
    fd_filestat_set_times: bool,
    path_symlink: bool,
    path_remove_directory: bool,
    path_unlink_file: bool,
    poll_fd_readwrite: bool,
    sock_shutdown: bool,
    sock_accept: bool,
};

const WasiFdFlags = packed struct {
    append: bool,
    dsync: bool,
    nonblock: bool,
    rsync: bool,
    sync: bool,
};

const Whence = enum(u8) {
    Set,
    Cur,
    End,

    fn fromInt(int: i32) ?Whence {
        return switch (int) {
            0 => .Set,
            1 => .Cur,
            2 => .End,
            else => null,
        };
    }
};

// Since the windows API is so large, wrapping the win32 API is not in the scope of the stdlib, so it
// prefers to only declare windows functions it uses. In these cases we just declare the needed functions
// and types here.
const WindowsApi = struct {
    const windows = std.os.windows;

    const BOOL = windows.BOOL;
    const DWORD = windows.DWORD;
    const FILETIME = windows.FILETIME;
    const HANDLE = windows.HANDLE;
    const LARGE_INTEGER = windows.LARGE_INTEGER;
    const ULONG = windows.ULONG;
    const WCHAR = windows.WCHAR;
    const WINAPI = windows.WINAPI;

    const CLOCK = struct {
        const REALTIME = 0;
        const MONOTONIC = 1;
        const PROCESS_CPUTIME_ID = 2;
        const THREAD_CPUTIME_ID = 3;
    };

    const BY_HANDLE_FILE_INFORMATION = extern struct {
        dwFileAttributes: DWORD,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        dwVolumeSerialNumber: DWORD,
        nFileSizeHigh: DWORD,
        nFileSizeLow: DWORD,
        nNumberOfLinks: DWORD,
        nFileIndexHigh: DWORD,
        nFileIndexLow: DWORD,
    };

    const FILE_ID_FULL_DIR_INFORMATION = extern struct {
        NextEntryOffset: ULONG,
        FileIndex: ULONG,
        CreationTime: LARGE_INTEGER,
        LastAccessTime: LARGE_INTEGER,
        LastWriteTime: LARGE_INTEGER,
        ChangeTime: LARGE_INTEGER,
        EndOfFile: LARGE_INTEGER,
        AllocationSize: LARGE_INTEGER,
        FileAttributes: ULONG,
        FileNameLength: ULONG,
        EaSize: ULONG,
        FileId: LARGE_INTEGER,
        FileName: [1]WCHAR,
    };

    extern "kernel32" fn GetSystemTimeAdjustment(timeAdjustment: *DWORD, timeIncrement: *DWORD, timeAdjustmentDisabled: *BOOL) callconv(WINAPI) BOOL;
    extern "kernel32" fn GetThreadTimes(in_hProcess: HANDLE, creationTime: *FILETIME, exitTime: *FILETIME, kernelTime: *FILETIME, userTime: *FILETIME) callconv(WINAPI) BOOL;
    extern "kernel32" fn GetFileInformationByHandle(file: HANDLE, fileInformation: *BY_HANDLE_FILE_INFORMATION) callconv(WINAPI) BOOL;
    const GetCurrentProcess = std.os.windows.kernel32.GetCurrentProcess;
};

const FD_WASI_INVALID = std.math.maxInt(u32);
const FD_OS_INVALID = switch (builtin.os.tag) {
    .windows => std.os.windows.INVALID_HANDLE_VALUE,
    else => -1,
};

const Helpers = struct {
    fn signedCast(comptime T: type, value: anytype, errno: *Errno) T {
        if (value >= 0) {
            return @intCast(T, value);
        }
        errno.* = Errno.INVAL;
        return 0;
    }

    fn writeIntToMemory(comptime T: type, value: T, offset: usize, module: *ModuleInstance, errno: *Errno) void {
        if (module.memoryWriteInt(T, value, offset) == false) {
            errno.* = Errno.INVAL;
        }
    }

    fn writeFilestatToMemory(stat: *const std.os.wasi.filestat_t, offset: u32, module: *ModuleInstance, errno: *Errno) void {
        const filetype = @enumToInt(stat.filetype);
        Helpers.writeIntToMemory(u64, stat.dev, offset + 0, module, errno);
        Helpers.writeIntToMemory(u64, stat.ino, offset + 8, module, errno);
        Helpers.writeIntToMemory(u8, filetype, offset + 16, module, errno);
        Helpers.writeIntToMemory(u64, stat.nlink, offset + 24, module, errno);
        Helpers.writeIntToMemory(u64, stat.size, offset + 32, module, errno);
        Helpers.writeIntToMemory(u64, stat.atim, offset + 40, module, errno);
        Helpers.writeIntToMemory(u64, stat.mtim, offset + 48, module, errno);
        Helpers.writeIntToMemory(u64, stat.ctim, offset + 56, module, errno);
    }

    fn stringsSizesGet(module: *ModuleInstance, strings: [][]const u8, params: []const Val, returns: []Val) void {
        const strings_count: u32 = @intCast(u32, strings.len);
        var strings_length: u32 = 0;
        for (strings) |string| {
            strings_length += @intCast(u32, string.len) + 1; // +1 for required null terminator of each string
        }

        var errno = Errno.SUCCESS;

        const dest_string_count = Helpers.signedCast(u32, params[0].I32, &errno);
        const dest_string_length = Helpers.signedCast(u32, params[1].I32, &errno);

        if (errno == .SUCCESS) {
            writeIntToMemory(u32, strings_count, dest_string_count, module, &errno);
            writeIntToMemory(u32, strings_length, dest_string_length, module, &errno);
        }

        returns[0] = Val{ .I32 = @enumToInt(errno) };
    }

    fn stringsGet(module: *ModuleInstance, strings: [][]const u8, params: []const Val, returns: []Val) void {
        var errno = Errno.SUCCESS;

        const dest_string_ptrs_begin = Helpers.signedCast(u32, params[0].I32, &errno);
        const dest_string_mem_begin = Helpers.signedCast(u32, params[1].I32, &errno);

        if (errno == .SUCCESS) {
            var dest_string_ptrs: u32 = dest_string_ptrs_begin;
            var dest_string_strings: u32 = dest_string_mem_begin;

            for (strings) |string| {
                writeIntToMemory(u32, dest_string_strings, dest_string_ptrs, module, &errno);

                var mem: []u8 = module.memorySlice(dest_string_strings, string.len + 1);
                std.mem.copy(u8, mem[0..string.len], string);
                mem[string.len] = 0; // null terminator

                dest_string_ptrs += @sizeOf(u32);
                dest_string_strings += @intCast(u32, string.len + 1);
            }
        }

        returns[0] = Val{ .I32 = @enumToInt(errno) };
    }

    fn convertClockId(wasi_clockid: i32, errno: *Errno) i32 {
        return switch (wasi_clockid) {
            std.os.wasi.CLOCK.REALTIME => if (builtin.os.tag != .windows) std.os.system.CLOCK.REALTIME else WindowsApi.CLOCK.REALTIME,
            std.os.wasi.CLOCK.MONOTONIC => if (builtin.os.tag != .windows) std.os.system.CLOCK.MONOTONIC else WindowsApi.CLOCK.MONOTONIC,
            std.os.wasi.CLOCK.PROCESS_CPUTIME_ID => if (builtin.os.tag != .windows) std.os.system.CLOCK.PROCESS_CPUTIME_ID else WindowsApi.CLOCK.PROCESS_CPUTIME_ID,
            std.os.wasi.CLOCK.THREAD_CPUTIME_ID => if (builtin.os.tag != .windows) std.os.system.CLOCK.THREAD_CPUTIME_ID else WindowsApi.CLOCK.THREAD_CPUTIME_ID,
            else => {
                errno.* = Errno.INVAL;
                return 0;
            },
        };
    }

    fn posixTimespecToWasi(ts: std.os.system.timespec) std.os.wasi.timestamp_t {
        const ns_per_second = 1000000000;
        const sec_part = @intCast(u64, ts.tv_sec);
        const nsec_part = @intCast(u64, ts.tv_nsec);
        const timestamp_ns: u64 = (sec_part * ns_per_second) + nsec_part;
        return timestamp_ns;
    }

    fn filetimeToU64(ft: std.os.windows.FILETIME) u64 {
        const v: u64 = (@intCast(u64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        return v;
    }

    fn windowsFiletimeToWasi(ft: std.os.windows.FILETIME) std.os.wasi.timestamp_t {
        // Windows epoch starts on Jan 1, 1601. Unix epoch starts on Jan 1, 1970.
        const win_epoch_to_unix_epoch_100ns: u64 = 116444736000000000;
        const timestamp_windows_100ns: u64 = Helpers.filetimeToU64(ft);

        const timestamp_100ns: u64 = timestamp_windows_100ns - win_epoch_to_unix_epoch_100ns;
        const timestamp_ns: u64 = timestamp_100ns * 100;
        return timestamp_ns;
    }

    fn decodeLookupFlags(value: i32) WasiLookupFlags {
        return WasiLookupFlags{
            .symlink_follow = (value & 0x01),
        };
    }

    fn decodeOpenFlags(value: i32) WasiOpenFlags {
        return WasiOpenFlags{
            .creat = (value & 0x01) != 0,
            .directory = (value & 0x02) != 0,
            .excl = (value & 0x04) != 0,
            .trunc = (value & 0x08) != 0,
        };
    }

    fn decodeRights(value: i64) WasiRights {
        return WasiRights{
            .fd_datasync = (value & 0x0001) != 0,
            .fd_read = (value & 0x0002) != 0,
            .fd_seek = (value & 0x0004) != 0,
            .fd_fdstat_set_flags = (value & 0x0008) != 0,

            .fd_sync = (value & 0x0010) != 0,
            .fd_tell = (value & 0x0020) != 0,
            .fd_write = (value & 0x0040) != 0,
            .fd_advise = (value & 0x0080) != 0,

            .fd_allocate = (value & 0x0100) != 0,
            .path_create_directory = (value & 0x0200) != 0,
            .path_create_file = (value & 0x0400) != 0,
            .path_link_source = (value & 0x0800) != 0,

            .path_link_target = (value & 0x1000) != 0,
            .path_open = (value & 0x2000) != 0,
            .fd_readdir = (value & 0x4000) != 0,
            .path_readlink = (value & 0x8000) != 0,

            .path_rename_source = (value & 0x10000) != 0,
            .path_rename_target = (value & 0x20000) != 0,
            .path_filestat_get = (value & 0x40000) != 0,
            .path_filestat_set_size = (value & 0x80000) != 0,

            .path_filestat_set_times = (value & 0x100000) != 0,
            .fd_filestat_get = (value & 0x200000) != 0,
            .fd_filestat_set_size = (value & 0x400000) != 0,
            .fd_filestat_set_times = (value & 0x800000) != 0,

            .path_symlink = (value & 0x1000000) != 0,
            .path_remove_directory = (value & 0x2000000) != 0,
            .path_unlink_file = (value & 0x4000000) != 0,
            .poll_fd_readwrite = (value & 0x8000000) != 0,

            .sock_shutdown = (value & 0x10000000) != 0,
            .sock_accept = (value & 0x20000000) != 0,
        };
    }

    fn decodeFdFlags(value: i32) WasiFdFlags {
        return WasiFdFlags{
            .append = (value & 0x01) != 0,
            .dsync = (value & 0x02) != 0,
            .nonblock = (value & 0x04) != 0,
            .rsync = (value & 0x08) != 0,
            .sync = (value & 0x10) != 0,
        };
    }

    fn windowsFileAttributeToWasiFiletype(fileAttributes: WindowsApi.DWORD) std.os.wasi.filetype_t {
        if (fileAttributes & std.os.windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
            return .DIRECTORY;
        } else if (fileAttributes & std.os.windows.FILE_ATTRIBUTE_REPARSE_POINT != 0) {
            return .SYMBOLIC_LINK;
        } else {
            return .REGULAR_FILE;
        }
    }

    fn posixModeToWasiFiletype(mode: std.os.mode_t) std.os.wasi.filetype_t {
        if (std.os.S.ISREG(mode)) {
            return .REGULAR_FILE;
        } else if (std.os.S.ISDIR(mode)) {
            return .DIRECTORY;
        } else if (std.os.S.ISCHR(mode)) {
            return .CHARACTER_DEVICE;
        } else if (std.os.S.ISBLK(mode)) {
            return .BLOCK_DEVICE;
        } else if (std.os.S.ISLNK(mode)) {
            return .SYMBOLIC_LINK;
            // } else if (std.os.S.ISSOCK(mode)) {
            //     stat_wasi.fs_filetype = std.os.wasi.filetype_t.SOCKET_STREAM; // not sure if this is SOCKET_STREAM or SOCKET_DGRAM
            // }
        } else {
            return .UNKNOWN;
        }
    }

    fn fdstat_get_windows(fd: std.os.fd_t, errno: *Errno) std.os.wasi.fdstat_t {
        if (builtin.os.tag != .windows) {
            @compileError("This function should only be called on the Windows OS.");
        }

        var stat_wasi = std.os.wasi.fdstat_t{
            .fs_filetype = std.os.wasi.filetype_t.REGULAR_FILE,
            .fs_flags = 0,
            .fs_rights_base = std.os.wasi.RIGHT.ALL,
            .fs_rights_inheriting = std.os.wasi.RIGHT.ALL,
        };

        var info: WindowsApi.BY_HANDLE_FILE_INFORMATION = undefined;
        if (WindowsApi.GetFileInformationByHandle(fd, &info) == std.os.windows.TRUE) {
            stat_wasi.fs_filetype = windowsFileAttributeToWasiFiletype(info.dwFileAttributes);

            if (info.dwFileAttributes & std.os.windows.FILE_ATTRIBUTE_READONLY != 0) {
                stat_wasi.fs_rights_base &= ~std.os.wasi.RIGHT.FD_WRITE;
            }
        } else |err| {
            errno.* = Errno.translateError(err);
        }

        return stat_wasi;
    }

    fn fdstat_get_posix(fd: std.os.fd_t, errno: *Errno) std.os.wasi.fdstat_t {
        if (builtin.os.tag == .windows) {
            @compileError("This function should only be called on an OS that supports posix APIs.");
        }

        var stat_wasi = std.os.wasi.fdstat_t{
            .fs_filetype = std.os.wasi.filetype_t.UNKNOWN,
            .fs_flags = 0,
            .fs_rights_base = std.os.wasi.RIGHT.ALL,
            .fs_rights_inheriting = std.os.wasi.RIGHT.ALL,
        };

        if (std.os.fcntl(fd, std.os.F.GETFL, 0)) |fd_flags| {
            if (std.os.fstat(fd)) |fd_stat| {

                // filetype
                stat_wasi.filetype = posixModeToWasiFiletype(fd_stat.mode);

                // flags
                if (fd_flags & std.os.O.APPEND) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.APPEND;
                }
                if (fd_flags & std.os.O.DSYNC) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.DSYNC;
                }
                if (fd_flags & std.os.O.NONBLOCK) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.NONBLOCK;
                }
                if (fd_flags & std.os.O.RSYNC) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.RSYNC;
                }
                if (fd_flags & std.os.O.SYNC) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.SYNC;
                }

                // rights
                if (fd_flags & std.os.O.RDWR) {
                    // noop since all rights includes this by default
                } else if (fd_flags & std.os.O.RDONLY) {
                    stat_wasi.fs_rights_base &= ~std.os.wasi.RIGHT.FD_WRITE;
                } else if (fd_flags & std.os.O.WRONLY) {
                    stat_wasi.fs_rights_base &= ~std.os.wasi.RIGHT.FD_READ;
                }
            } else |err| {
                errno = Errno.translateError(err);
            }
        } else |err| {
            errno = Errno.translateError(err);
        }

        return stat_wasi;
    }

    fn partsToU64(high: u64, low: u64) u64 {
        return (high << 32) | low;
    }

    fn filestat_get_windows(fd: std.os.fd_t, errno: *Errno) std.os.wasi.filestat_t {
        if (builtin.os.tag != .windows) {
            @compileError("This function should only be called on an OS that supports posix APIs.");
        }

        var stat_wasi: std.os.wasi.filestat_t = undefined;

        var info: WindowsApi.BY_HANDLE_FILE_INFORMATION = undefined;
        if (WindowsApi.GetFileInformationByHandle(fd, &info) == std.os.windows.TRUE) {
            stat_wasi.dev = 0;
            stat_wasi.ino = partsToU64(info.nFileIndexHigh, info.nFileIndexLow);
            stat_wasi.filetype = windowsFileAttributeToWasiFiletype(info.dwFileAttributes);
            stat_wasi.nlink = info.nNumberOfLinks;
            stat_wasi.size = partsToU64(info.nFileSizeHigh, info.nFileSizeLow);
            stat_wasi.atim = windowsFiletimeToWasi(info.ftLastAccessTime);
            stat_wasi.mtim = windowsFiletimeToWasi(info.ftLastWriteTime);
            stat_wasi.ctim = windowsFiletimeToWasi(info.ftCreationTime);
        } else |err| {
            errno.* = Errno.translateError(err);
        }

        return stat_wasi;
    }

    fn filestat_get_posix(fd: std.os.fd_t, errno: *Errno) std.os.wasi.filestat_t {
        if (builtin.os.tag == .windows) {
            @compileError("This function should only be called on an OS that supports posix APIs.");
        }

        var stat_wasi: std.os.wasi.filestat_t = undefined;

        if (std.os.fstat(fd)) |stat| {
            stat_wasi.dev = stat.dev;
            stat_wasi.ino = stat.ino;
            stat_wasi.filetype = posixModeToWasiFiletype(stat.mode);
            stat_wasi.nlink = stat.nlink;
            stat_wasi.size = stat.size;
            stat_wasi.atim = posixTimespecToWasi(stat.atim);
            stat_wasi.mtim = posixTimespecToWasi(stat.mtim);
            stat_wasi.ctim = posixTimespecToWasi(stat.ctim);
        } else |err| {
            errno = Errno.translateError(err);
        }

        return stat_wasi;
    }

    fn enumerateDirEntriesWindows(fd_info: *const WasiContext.FdInfo, cookie: u64, out_buffer: []u8, errno: *Errno) u32 {
        var static_path_buffer: [std.fs.MAX_PATH_BYTES * 2]u8 = undefined;

        var restart_scan: std.os.windows.BOOLEAN = std.os.windows.TRUE;
        comptime std.debug.assert(std.os.wasi.DIRCOOKIE_START == 0);

        // Always rescan up to the cookie index since win32 api doesn't have a way to specify a "start index"
        // for the scan. :(
        const entries_to_skip: u64 = cookie;

        var fbs = std.io.fixedBufferStream(out_buffer);
        var writer = fbs.writer();

        var file_index: usize = 0;
        var should_continue: bool = true;
        while (should_continue) {
            var file_info_buffer: [1024]u8 align(@alignOf(WindowsApi.FILE_ID_FULL_DIR_INFORMATION)) = undefined;
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var rc: std.os.windows.NTSTATUS = std.os.windows.ntdll.NtQueryDirectoryFile(
                fd_info.fd,
                null,
                null,
                null,
                &io,
                &file_info_buffer,
                file_info_buffer.len,
                .FileIdFullDirectoryInformation,
                std.os.windows.TRUE,
                null,
                restart_scan,
            );
            switch (rc) {
                .SUCCESS => {},
                .NO_MORE_FILES => {
                    should_continue = false;
                },
                .BUFFER_OVERFLOW => {
                    std.debug.print("Internal buffer is too small.\n", .{});
                    unreachable;
                },
                .INVALID_INFO_CLASS => unreachable,
                .INVALID_PARAMETER => unreachable,
                else => |err| {
                    std.debug.print("NtQueryDirectoryFile: err {}", .{err});
                    unreachable;
                },
            }

            restart_scan = std.os.windows.FALSE;

            if (entries_to_skip <= file_index and rc == .SUCCESS) {
                const file_info = @ptrCast(*WindowsApi.FILE_ID_FULL_DIR_INFORMATION, &file_info_buffer);

                const filename_utf16le = @ptrCast([*]u16, &file_info.FileName)[0 .. file_info.FileNameLength / @sizeOf(u16)];

                var fba = std.heap.FixedBufferAllocator.init(&static_path_buffer);
                var allocator = fba.allocator();
                const filename: []u8 = std.unicode.utf16leToUtf8Alloc(allocator, filename_utf16le) catch unreachable;

                var filetype: std.os.wasi.filetype_t = .REGULAR_FILE;
                if (file_info.FileAttributes & std.os.windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
                    filetype = .DIRECTORY;
                } else if (file_info.FileAttributes & std.os.windows.FILE_ATTRIBUTE_REPARSE_POINT != 0) {
                    filetype = .SYMBOLIC_LINK;
                }

                writer.writeIntLittle(u64, file_index) catch break;
                writer.writeIntLittle(u64, @bitCast(u64, file_info.FileId)) catch break; // inode
                writer.writeIntLittle(u32, signedCast(u32, filename.len, errno)) catch break;
                writer.writeIntLittle(u32, @enumToInt(filetype)) catch break;
                _ = writer.write(filename) catch break;
            }

            file_index += 1;
        }

        var bytes_written = signedCast(u32, fbs.pos, errno);
        return bytes_written;
    }

    fn enumerateDirEntriesPosix(fd_info: *const WasiContext.FdInfo, cookie: u64, out_buffer: []u8, errno: *Errno) u32 {
        _ = fd_info;
        _ = cookie;
        _ = out_buffer;
        _ = errno;

        // TODO
        unreachable;

        // return 0;
    }

    fn initIovecs(comptime iov_type: type, stack_iov: []iov_type, errno: *Errno, module: *ModuleInstance, iovec_array_begin: u32, iovec_array_count: u32) ?[]iov_type {
        if (iovec_array_count < stack_iov.len) {
            const iov = stack_iov[0..iovec_array_count];
            const iovec_array_bytes_length = @sizeOf(u32) * 2 * iovec_array_count;
            const iovec_mem: []const u8 = module.memorySlice(iovec_array_begin, iovec_array_bytes_length);
            var stream = std.io.fixedBufferStream(iovec_mem);
            var reader = stream.reader();

            for (iov) |*iovec| {
                const iov_base: u32 = reader.readIntLittle(u32) catch {
                    errno.* = Errno.INVAL;
                    return null;
                };

                const iov_len: u32 = reader.readIntLittle(u32) catch {
                    errno.* = Errno.INVAL;
                    return null;
                };

                const mem: []u8 = module.memorySlice(iov_base, iov_len);
                iovec.iov_base = mem.ptr;
                iovec.iov_len = mem.len;
            }

            return iov;
        } else {
            errno.* = Errno.TOOBIG;
        }

        return null;
    }
};

fn wasi_proc_exit(_: ?*anyopaque, _: *ModuleInstance, params: []const Val, _: []Val) void {
    const raw_exit_code = params[0].I32;

    if (raw_exit_code >= 0 and raw_exit_code < std.math.maxInt(u8)) {
        const exit_code = @intCast(u8, raw_exit_code);
        std.os.exit(exit_code);
    } else {
        std.os.exit(1);
    }
}

fn wasi_args_sizes_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsSizesGet(module, context.argv, params, returns);
}

fn wasi_args_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsGet(module, context.argv, params, returns);
}

fn wasi_environ_sizes_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsSizesGet(module, context.env, params, returns);
}

fn wasi_environ_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsGet(module, context.env, params, returns);
}

fn wasi_clock_res_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const system_clockid: i32 = Helpers.convertClockId(params[0].I32, &errno);
    const timestamp_mem_begin = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        var freqency_ns: u64 = 0;
        if (builtin.os.tag == .windows) {
            // Follow the mingw pattern since clock_getres() isn't linked in libc for windows
            if (system_clockid == std.os.wasi.CLOCK.REALTIME or system_clockid == std.os.wasi.CLOCK.MONOTONIC) {
                const ns_per_second: u64 = 1000000000;
                const tick_frequency: u64 = std.os.windows.QueryPerformanceFrequency();
                freqency_ns = (ns_per_second + (tick_frequency >> 1)) / tick_frequency;
                if (freqency_ns < 1) {
                    freqency_ns = 1;
                }
            } else {
                var timeAdjustment: WindowsApi.DWORD = undefined;
                var timeIncrement: WindowsApi.DWORD = undefined;
                var timeAdjustmentDisabled: WindowsApi.BOOL = undefined;
                if (WindowsApi.GetSystemTimeAdjustment(&timeAdjustment, &timeIncrement, &timeAdjustmentDisabled) == std.os.windows.TRUE) {
                    freqency_ns = timeIncrement * 100;
                } else {
                    errno = Errno.INVAL;
                }
            }
        } else {
            var ts: std.os.system.timespec = undefined;
            if (std.os.clock_getres(system_clockid, &ts)) {
                freqency_ns = @intCast(u64, ts.tv_nsec);
            } else |_| {
                errno = Errno.INVAL;
            }
        }

        Helpers.writeIntToMemory(u64, freqency_ns, timestamp_mem_begin, module, &errno);
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_clock_time_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const system_clockid: i32 = Helpers.convertClockId(params[0].I32, &errno);
    //const precision = params[1].I64; // unused
    const timestamp_mem_begin = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        const ns_per_second = 1000000000;
        var timestamp_ns: u64 = 0;

        if (builtin.os.tag == .windows) {
            switch (system_clockid) {
                std.os.wasi.CLOCK.REALTIME => {
                    var ft: WindowsApi.FILETIME = undefined;
                    std.os.windows.kernel32.GetSystemTimeAsFileTime(&ft);

                    timestamp_ns = Helpers.windowsFiletimeToWasi(ft);
                },
                std.os.wasi.CLOCK.MONOTONIC => {
                    const ticks: u64 = std.os.windows.QueryPerformanceCounter();
                    const ticks_per_second: u64 = std.os.windows.QueryPerformanceFrequency();

                    // break up into 2 calculations to avoid overflow
                    const timestamp_secs_part: u64 = ticks / ticks_per_second;
                    const timestamp_ns_part: u64 = ((ticks % ticks_per_second) * ns_per_second + (ticks_per_second >> 1)) / ticks_per_second;

                    timestamp_ns = timestamp_secs_part + timestamp_ns_part;
                },
                std.os.wasi.CLOCK.PROCESS_CPUTIME_ID => {
                    var createTime: WindowsApi.FILETIME = undefined;
                    var exitTime: WindowsApi.FILETIME = undefined;
                    var kernelTime: WindowsApi.FILETIME = undefined;
                    var userTime: WindowsApi.FILETIME = undefined;
                    if (std.os.windows.kernel32.GetProcessTimes(WindowsApi.GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime) == std.os.windows.TRUE) {
                        const timestamp_100ns: u64 = Helpers.filetimeToU64(kernelTime) + Helpers.filetimeToU64(userTime);
                        timestamp_ns = timestamp_100ns * 100;
                    } else {
                        errno = Errno.INVAL;
                    }
                },
                std.os.wasi.CLOCK.THREAD_CPUTIME_ID => {
                    var createTime: WindowsApi.FILETIME = undefined;
                    var exitTime: WindowsApi.FILETIME = undefined;
                    var kernelTime: WindowsApi.FILETIME = undefined;
                    var userTime: WindowsApi.FILETIME = undefined;
                    if (WindowsApi.GetThreadTimes(WindowsApi.GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime) == std.os.windows.TRUE) {
                        const timestamp_100ns: u64 = Helpers.filetimeToU64(kernelTime) + Helpers.filetimeToU64(userTime);
                        timestamp_ns = timestamp_100ns * 100;
                    } else {
                        errno = Errno.INVAL;
                    }
                },
                else => unreachable,
            }
        } else {
            var ts: std.os.system.timespec = undefined;
            if (std.os.clock_gettime(system_clockid, &ts)) {
                timestamp_ns = Helpers.posixTimespecToWasi(ts);
            } else |_| {
                errno = Errno.INVAL;
            }
        }

        Helpers.writeIntToMemory(u64, timestamp_ns, timestamp_mem_begin, module, &errno);
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_datasync(userdata: ?*anyopaque, _: *ModuleInstance, params: []const Val, returns: []Val) void {
    const context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);

    var errno = Errno.SUCCESS;

    if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
        std.os.fdatasync(fd_info.fd) catch |err| {
            errno = Errno.translateError(err);
        };
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_fdstat_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const fdstat_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            const fd_os: std.os.fd_t = fd_info.fd;
            const stat: std.os.wasi.fdstat_t = if (builtin.os.tag == .windows) Helpers.fdstat_get_windows(fd_os, &errno) else Helpers.fdstat_get_posix(fd_os, &errno);

            if (errno == .SUCCESS) {
                Helpers.writeIntToMemory(u8, @enumToInt(stat.fs_filetype), fdstat_mem_offset + 0, module, &errno);
                Helpers.writeIntToMemory(u16, stat.fs_flags, fdstat_mem_offset + 2, module, &errno);
                Helpers.writeIntToMemory(u64, stat.fs_rights_base, fdstat_mem_offset + 8, module, &errno);
                Helpers.writeIntToMemory(u64, stat.fs_rights_inheriting, fdstat_mem_offset + 16, module, &errno);
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_fdstat_set_flags(_: ?*anyopaque, _: *ModuleInstance, params: []const Val, returns: []Val) void {
    std.debug.assert(params.len == 2);
    std.debug.assert(std.meta.activeTag(params[0]) == .I32);
    std.debug.assert(std.meta.activeTag(params[1]) == .I32);
    std.debug.assert(returns.len == 1);

    // std.debug.print("called wasi_fd_fdstat_set_flags\n", .{});

    // TODO
    var errno = Errno.SUCCESS;
    returns[0] = Val{ .I32 = @enumToInt(errno) };

    unreachable;
}

fn wasi_fd_prestat_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_dir_wasi = @bitCast(u32, params[0].I32);
    const prestat_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        // std.debug.print("attempt to lookup fd_dir_wasi {}\n", .{fd_dir_wasi});
        if (context.fdDirPath(fd_dir_wasi, &errno)) |path_source| {
            // var name_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            // const path: []const u8 = std.os.getFdPath(fd_os.?, &name_buffer) catch unreachable;
            // std.debug.print("wasi_fd_prestat_get: fd_dir_wasi {} -> path: {s}\n", .{ fd_dir_wasi, path_source });
            const pr_name_len: u32 = @intCast(u32, path_source.len + 1); // allow space for null terminator

            Helpers.writeIntToMemory(u32, std.os.wasi.PREOPENTYPE_DIR, prestat_mem_offset + 0, module, &errno);
            Helpers.writeIntToMemory(u32, pr_name_len, prestat_mem_offset + @sizeOf(u32), module, &errno);
        }
    }

    // std.debug.print("wasi_fd_prestat_get errno: {}\n", .{errno});

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_prestat_dir_name(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_dir_wasi = Helpers.signedCast(u32, params[0].I32, &errno);
    const path_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);
    const path_mem_length = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdDirPath(fd_dir_wasi, &errno)) |path_source| {
            // std.debug.print("wasi_fd_prestat_dir_name: fd_dir_wasi {} -> path: {s}\n", .{ fd_dir_wasi, path_source });
            var path_dest: []u8 = module.memorySlice(path_mem_offset, path_mem_length);
            std.mem.copy(u8, path_dest, path_source);
            const null_offset: usize = std.math.min(path_source.len, path_dest.len);
            path_dest[null_offset] = 0; // null terminator
        }
    }

    // std.debug.print("wasi_fd_prestat_dir_name errno: {}\n", .{errno});

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_read(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const bytes_read_out_offset = Helpers.signedCast(u32, params[3].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            var stack_iov = [_]std.os.iovec{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.readv(fd_info.fd, iov)) |read_bytes| {
                    if (read_bytes <= std.math.maxInt(u32)) {
                        Helpers.writeIntToMemory(u32, @intCast(u32, read_bytes), bytes_read_out_offset, module, &errno);
                    } else {
                        errno = Errno.TOOBIG;
                    }
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_readdir(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const dirent_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);
    const dirent_mem_length = Helpers.signedCast(u32, params[2].I32, &errno);
    const cookie = Helpers.signedCast(u64, params[3].I64, &errno);
    const bytes_written_out_offset = Helpers.signedCast(u32, params[4].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            // TODO wrap access to memorySlice in a helper that sets errno
            var dirent_buffer: []u8 = module.memorySlice(dirent_mem_offset, dirent_mem_length);
            const enumFunc = if (builtin.os.tag == .windows) Helpers.enumerateDirEntriesWindows else Helpers.enumerateDirEntriesPosix;
            var bytes_written = enumFunc(fd_info, cookie, dirent_buffer, &errno);
            Helpers.writeIntToMemory(u32, bytes_written, bytes_written_out_offset, module, &errno);
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_pread(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const read_offset = @bitCast(u64, params[3].I64);
    const bytes_read_out_offset = Helpers.signedCast(u32, params[4].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            var stack_iov = [_]std.os.iovec{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.preadv(fd_info.fd, iov, read_offset)) |read_bytes| {
                    if (read_bytes <= std.math.maxInt(u32)) {
                        Helpers.writeIntToMemory(u32, @intCast(u32, read_bytes), bytes_read_out_offset, module, &errno);
                    } else {
                        errno = Errno.TOOBIG;
                    }
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_close(userdata: ?*anyopaque, _: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);

    const fd_wasi = @bitCast(u32, params[0].I32);

    if (errno == .SUCCESS) {
        if (context.fdRemove(fd_wasi)) |fd_os| {
            std.os.close(fd_os);
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_filestat_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const filestat_out_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            const stat: std.os.wasi.filestat_t = if (builtin.os.tag == .windows) Helpers.filestat_get_windows(fd_info.fd, &errno) else Helpers.filestat_get_posix(fd_info.fd, &errno);
            if (errno == .SUCCESS) {
                Helpers.writeFilestatToMemory(&stat, filestat_out_mem_offset, module, &errno);
            } else |err| {
                errno = Errno.translateError(err);
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_seek(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const offset = params[1].I64;
    const whence_raw = params[2].I32;
    const filepos_out_offset = Helpers.signedCast(u32, params[3].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            const fd_os: std.os.fd_t = fd_info.fd;
            if (Whence.fromInt(whence_raw)) |whence| {
                switch (whence) {
                    .Set => {
                        if (offset >= 0) {
                            const offset_unsigned = @intCast(u64, offset);
                            std.os.lseek_SET(fd_os, offset_unsigned) catch |err| {
                                errno = Errno.translateError(err);
                            };
                        }
                    },
                    .Cur => {
                        std.os.lseek_CUR(fd_os, offset) catch |err| {
                            errno = Errno.translateError(err);
                        };
                    },
                    .End => {
                        std.os.lseek_END(fd_os, offset) catch |err| {
                            errno = Errno.translateError(err);
                        };
                    },
                }

                if (std.os.lseek_CUR_get(fd_os)) |filepos| {
                    Helpers.writeIntToMemory(u64, filepos, filepos_out_offset, module, &errno);
                } else |err| {
                    errno = Errno.translateError(err);
                }
            } else {
                errno = Errno.INVAL;
            }
        }
    }
    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_tell(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);

    const fd_wasi = @bitCast(u32, params[0].I32);
    const filepos_out_offset = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            if (std.os.lseek_CUR_get(fd_info.fd)) |filepos| {
                Helpers.writeIntToMemory(u64, filepos, filepos_out_offset, module, &errno);
            } else |err| {
                errno = Errno.translateError(err);
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_write(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const bytes_written_out_offset = Helpers.signedCast(u32, params[3].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            var stack_iov = [_]std.os.iovec_const{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec_const, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.writev(fd_info.fd, iov)) |written_bytes| {
                    Helpers.writeIntToMemory(u32, @intCast(u32, written_bytes), bytes_written_out_offset, module, &errno);
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_pwrite(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const write_offset = Helpers.signedCast(u64, params[3].I64, &errno);
    const bytes_written_out_offset = Helpers.signedCast(u32, params[4].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi, &errno)) |fd_info| {
            var stack_iov = [_]std.os.iovec_const{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec_const, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.pwritev(fd_info.fd, iov, write_offset)) |written_bytes| {
                    Helpers.writeIntToMemory(u32, @intCast(u32, written_bytes), bytes_written_out_offset, module, &errno);
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_path_filestat_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_dir_wasi = @bitCast(u32, params[0].I32);
    const lookup_flags = @bitCast(u32, params[1].I32);
    const path_mem_offset: u32 = Helpers.signedCast(u32, params[2].I32, &errno);
    const path_mem_length: u32 = Helpers.signedCast(u32, params[3].I32, &errno);
    const filestat_out_mem_offset = Helpers.signedCast(u32, params[4].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_dir_wasi, &errno)) |fd_info| {
            const path: []const u8 = module.memorySlice(path_mem_offset, path_mem_length);
            if (context.hasPathAccess(fd_info, path, &errno)) {
                var flags: u32 = std.os.O.RDONLY;
                if ((lookup_flags & std.os.wasi.LOOKUP_SYMLINK_FOLLOW) == 0) {
                    flags |= std.os.O.NOFOLLOW;
                }

                const mode: std.os.mode_t = if (builtin.os.tag != .windows) 644 else undefined;

                if (std.os.openat(fd_info.fd, path, flags, mode)) |fd_opened| {
                    defer std.os.close(fd_opened);

                    const stat: std.os.wasi.filestat_t = if (builtin.os.tag == .windows) Helpers.filestat_get_windows(fd_opened, &errno) else Helpers.filestat_get_posix(fd_opened, &errno);
                    if (errno == .SUCCESS) {
                        Helpers.writeFilestatToMemory(&stat, filestat_out_mem_offset, module, &errno);
                    }
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_path_open(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_dir_wasi: u32 = Helpers.signedCast(u32, params[0].I32, &errno);
    // const dirflags: WasiLookupFlags = Helpers.decodeLookupFlags(params[1].I32);
    const path_mem_offset: u32 = Helpers.signedCast(u32, params[2].I32, &errno);
    const path_mem_length: u32 = Helpers.signedCast(u32, params[3].I32, &errno);
    const openflags: WasiOpenFlags = Helpers.decodeOpenFlags(params[4].I32);
    const rights_base: WasiRights = Helpers.decodeRights(params[5].I64);
    // const rights_inheriting: WasiRights = Helpers.decodeRights(params[6].I64);
    const fdflags: WasiFdFlags = Helpers.decodeFdFlags(params[7].I32);
    const fd_out_mem_offset = Helpers.signedCast(u32, params[8].I32, &errno);

    // std.debug.print("path_open oflags: {}, rights: {}, fdflags: {x}\n", .{ openflags, rights_base, params[7].I32 });

    if (errno == .SUCCESS) {
        const path: []const u8 = module.memorySlice(path_mem_offset, path_mem_length);

        if (context.fdLookup(fd_dir_wasi, &errno)) |fd_info| {
            if (context.hasPathAccess(fd_info, path, &errno)) {
                var flags: u32 = 0;
                if (openflags.creat) {
                    flags |= std.os.O.CREAT;
                    // std.os.open() windows implementation requires exclusive flag to create files
                    if (builtin.os.tag == .windows) {
                        flags |= std.os.O.EXCL;
                    }
                }
                if (openflags.directory) {
                    flags |= std.os.O.DIRECTORY;
                }
                if (openflags.excl) {
                    flags |= std.os.O.EXCL;
                }
                if (openflags.trunc) {
                    flags |= std.os.O.TRUNC;
                }

                if (fdflags.append) {
                    flags |= std.os.O.APPEND;
                }
                if (fdflags.dsync) {
                    flags |= std.os.O.DSYNC;
                }
                if (fdflags.nonblock) {
                    flags |= std.os.O.NONBLOCK;
                }
                if (fdflags.rsync) {
                    flags |= std.os.O.RSYNC;
                }
                if (fdflags.sync) {
                    flags |= std.os.O.SYNC;
                }

                if (rights_base.fd_read and rights_base.fd_write) {
                    flags |= std.os.O.RDWR;
                } else if (rights_base.fd_read) {
                    flags |= std.os.O.RDONLY;
                } else if (rights_base.fd_write) {
                    flags |= std.os.O.WRONLY;
                }

                // 644 means rw perm owner, r perm group, r perm others
                var mode: std.os.mode_t = if (builtin.os.tag != .windows) 644 else undefined;

                if (context.fdOpen(fd_info.fd, path, flags, mode, &errno)) |fd_opened_wasi| {
                    Helpers.writeIntToMemory(u32, fd_opened_wasi, fd_out_mem_offset, module, &errno);
                }
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_path_remove_directory(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);

    const fd_dir_wasi = Helpers.signedCast(u32, params[0].I32, &errno);
    const path_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);
    const path_mem_length = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        const path: []const u8 = module.memorySlice(path_mem_offset, path_mem_length);
        if (context.fdLookup(fd_dir_wasi, &errno)) |fd_info| {
            if (context.hasPathAccess(fd_info, path, &errno)) {
                std.os.unlinkat(fd_info.fd, path, std.os.AT.REMOVEDIR) catch |err| {
                    errno = Errno.translateError(err);
                };
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_path_unlink_file(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);

    const fd_dir_wasi = Helpers.signedCast(u32, params[0].I32, &errno);
    const path_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);
    const path_mem_length = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        const path: []const u8 = module.memorySlice(path_mem_offset, path_mem_length);
        // std.debug.print("unlink file '{s}'\n", .{path});

        if (context.fdLookup(fd_dir_wasi, &errno)) |fd_info| {
            if (context.hasPathAccess(fd_info, path, &errno)) {
                std.os.unlinkat(fd_info.fd, path, 0) catch |err| {
                    // std.debug.print("unlinkat error: {} at dir {s} with path {s}\n", .{ err, fd_info.path_absolute, path });
                    errno = Errno.translateError(err);
                };
            }
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_random_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const array_begin_offset: u32 = Helpers.signedCast(u32, params[0].I32, &errno);
    const array_length: u32 = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        if (array_length > 0) {
            var mem: []u8 = module.memorySlice(array_begin_offset, array_length);
            std.crypto.random.bytes(mem);
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

pub const WasiOpts = struct {
    argv: ?[][]const u8 = null,
    env: ?[][]const u8 = null,
    dirs: ?[][]const u8 = null,
};

pub fn initImports(opts: WasiOpts, allocator: std.mem.Allocator) WasiInitError!ModuleImports {
    var context: *WasiContext = try allocator.create(WasiContext);
    errdefer allocator.destroy(context);
    context.* = try WasiContext.init(&opts, allocator);
    errdefer context.deinit();

    var imports: ModuleImports = try ModuleImports.init("wasi_snapshot_preview1", null, context, allocator);

    const void_returns = &[0]ValType{};

    try imports.addHostFunction("args_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_args_get);
    try imports.addHostFunction("args_sizes_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_args_sizes_get);
    try imports.addHostFunction("clock_res_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_clock_res_get);
    try imports.addHostFunction("clock_time_get", &[_]ValType{ .I32, .I64, .I32 }, &[_]ValType{.I32}, wasi_clock_time_get);
    try imports.addHostFunction("environ_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_environ_get);
    try imports.addHostFunction("environ_sizes_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_environ_sizes_get);
    try imports.addHostFunction("fd_close", &[_]ValType{.I32}, &[_]ValType{.I32}, wasi_fd_close);
    try imports.addHostFunction("fd_datasync", &[_]ValType{.I32}, &[_]ValType{.I32}, wasi_fd_datasync);
    try imports.addHostFunction("fd_fdstat_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_fdstat_get);
    try imports.addHostFunction("fd_fdstat_set_flags", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_fdstat_set_flags);
    try imports.addHostFunction("fd_filestat_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_filestat_get);
    try imports.addHostFunction("fd_prestat_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_prestat_get);
    try imports.addHostFunction("fd_prestat_dir_name", &[_]ValType{ .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_prestat_dir_name);
    try imports.addHostFunction("fd_read", &[_]ValType{ .I32, .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_read);
    try imports.addHostFunction("fd_readdir", &[_]ValType{ .I32, .I32, .I32, .I64, .I32 }, &[_]ValType{.I32}, wasi_fd_readdir);
    try imports.addHostFunction("fd_pread", &[_]ValType{ .I32, .I32, .I32, .I64, .I32 }, &[_]ValType{.I32}, wasi_fd_pread);
    try imports.addHostFunction("fd_seek", &[_]ValType{ .I32, .I64, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_seek);
    try imports.addHostFunction("fd_tell", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_tell);
    try imports.addHostFunction("fd_write", &[_]ValType{ .I32, .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_write);
    try imports.addHostFunction("fd_pwrite", &[_]ValType{ .I32, .I32, .I32, .I64, .I32 }, &[_]ValType{.I32}, wasi_fd_pwrite);
    try imports.addHostFunction("random_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_random_get);
    try imports.addHostFunction("path_filestat_get", &[_]ValType{ .I32, .I32, .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_path_filestat_get);
    try imports.addHostFunction("path_open", &[_]ValType{ .I32, .I32, .I32, .I32, .I32, .I64, .I64, .I32, .I32 }, &[_]ValType{.I32}, wasi_path_open);
    try imports.addHostFunction("path_remove_directory", &[_]ValType{ .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_path_remove_directory);
    try imports.addHostFunction("path_unlink_file", &[_]ValType{ .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_path_unlink_file);
    try imports.addHostFunction("proc_exit", &[_]ValType{.I32}, void_returns, wasi_proc_exit);

    return imports;
}

pub fn deinitImports(imports: *ModuleImports) void {
    var context = WasiContext.fromUserdata(imports.userdata);
    context.deinit();
    imports.allocator.destroy(context);

    imports.deinit();
}
