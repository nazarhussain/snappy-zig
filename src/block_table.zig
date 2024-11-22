const std = @import("std");

pub const MAX_TABLE_SIZE: usize = 1 << 14;
pub const SMALL_TABLE_SIZE: usize = 1 << 10;

pub const BlockTable = struct {
    table: []u16,

    /// The number of bits required to shift the hash such that the result
    /// is less than table.len().
    shift: u32,

    pub fn hash(self: BlockTable, val: usize) usize {
        return @as(u32, @intCast(val)) *% 0x1E35A7BD >> @intCast(self.shift);
    }

    pub fn get(self: BlockTable, index: usize) u16 {
        return self.table[index];
    }

    pub fn set(self: BlockTable, index: usize, val: u16) void {
        self.table[index] = val;
    }

    pub fn free(self: BlockTable, allocator: std.mem.Allocator) void {
        allocator.free(self.table);
    }
};

pub fn new(block_size: usize, allocator: std.mem.Allocator) !BlockTable {
    var shift: u32 = 32 - 8;
    var table_size: usize = 256;

    while (table_size < MAX_TABLE_SIZE and table_size < block_size) {
        shift -= 1;
        table_size *= 2;
    }

    const table = allocator.alloc(u16, MAX_TABLE_SIZE) catch |err| {
        const err_message = try std.fmt.allocPrint(allocator, "Input is too large {s}", .{@errorName(err)});
        defer allocator.free(err_message);
        @panic(err_message);
    };
    errdefer allocator.free(table);

    @memset(table, 0);

    return BlockTable{ .table = table, .shift = shift };
}
