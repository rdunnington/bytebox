const std = @import("std");

pub fn decodeLEB128(comptime T: type, reader: anytype) !T {
    if (@typeInfo(T).Int.signedness == .signed) {
        return std.leb.readILEB128(T, reader) catch |e| {
            if (e == error.Overflow) {
                return error.MalformedLEB128;
            } else {
                return e;
            }
        };
    } else {
        return std.leb.readULEB128(T, reader) catch |e| {
            if (e == error.Overflow) {
                return error.MalformedLEB128;
            } else {
                return e;
            }
        };
    }
}
