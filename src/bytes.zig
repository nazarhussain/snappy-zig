const std = @import("std");
const testing = std.testing;

pub fn load_32(array: []const u8, pos: usize) u32 {
    return std.mem.readPackedInt(u32, array, pos * 8, std.builtin.Endian.little);
}

pub fn equals_32(array: []const u8, pos1: usize, pos2: usize) bool {
    return std.mem.readPackedInt(u32, array, pos1 * 8, std.builtin.Endian.little) == std.mem.readPackedInt(u32, array, pos2 * 8, std.builtin.Endian.little);
}

pub fn write_16_int_le(num: usize, dest: [*]u8) void {
    var val = num;

    dest[0] = @intCast(val & 0xFF);
    val >>= 8;
    dest[1] = @intCast(val & 0xFF);
}

pub fn write_32_int_le(num: usize, dest: [*]u8) void {
    var val = num;

    for (0..3) |i| {
        dest[i] = @intCast(val & 0xFF);
        val >>= 8;
    }
}

pub fn get_byte_size(value: usize) u8 {
    if (value == 0) return 1; // 0 requires at least 1 byte

    const bits = @bitSizeOf(usize) - @clz(value); // Count significant bits
    return (bits + 7) / 8; // Round up to the nearest byte
}

pub fn trailing_zeros(n: usize) usize {
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

pub fn write_varint(num: usize, dest: []u8, start: usize) usize {
    var n = num;
    var i: usize = start;
    while (n >= 0b1000_0000) {
        dest[i] = @intCast((n & 0b0111_1111) | 0b1000_0000);
        n >>= 7;
        i += 1;
    }

    dest[i] = @intCast(n);

    return i + 1;
}

test "varint 64" {
    var dest = [1]u8{0};
    const size = write_varint(64, dest[0..], 0);

    try testing.expectEqual(size, 1);
    try testing.expectEqual(dest, .{0x40});
}

test "varint 2097150" {
    var dest = [3]u8{ 0, 0, 0 };
    const size = write_varint(2097150, dest[0..], 0);

    try testing.expectEqual(size, 3);
    try testing.expectEqual(dest, .{ 0xFE, 0xFF, 0x7F });
}
