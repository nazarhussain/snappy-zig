const std = @import("std");

pub fn load_32(array: []const u8, pos: usize) u32 {
    return std.mem.readPackedInt(u32, array, pos * 8, std.builtin.Endian.little);
}

pub fn equals_32(array: []const u8, pos1: usize, pos2: usize) bool {
    return std.mem.readPackedInt(u32, array, pos1 * 8, std.builtin.Endian.little) == std.mem.readPackedInt(u32, array, pos2 * 8, std.builtin.Endian.little);
}

pub fn write_u16_le(n: u16, dest: [*]u8) void {
    var val: u8 = @intCast(n & 0x00FF);
    dest[0] = val;
    val = @intCast(n >> 8);
    dest[1] = val;
}

pub fn trailing_zerors(n: usize) usize {
    var res: usize = 0;
    var num = n;

    while (num > 0) {
        if (num & 0b1 == 0) {
            res += 1;
        } else {
            break;
        }
        num = num >> 1;
    }

    return res;
}
