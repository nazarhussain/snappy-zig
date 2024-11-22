const std = @import("std");
const block = @import("./block.zig");
const block_table = @import("./block_table.zig");

const MAX_INPUT_SIZE = std.math.maxInt(u32);
const MAX_BLOCK_SIZE = 1 << 16;

pub fn max_compress_len(input_len: usize) !SnappyError!usize {
    if (input_len > MAX_INPUT_SIZE) {
        return SnappyError.LargeInput;
    }
    const max = 32 + input_len + (input_len / 6);

    if (max > MAX_INPUT_SIZE) {
        return SnappyError.LargeInput;
    } else {
        return max;
    }
}

const SnappyError = error{ EmptyInput, LargeInput };

pub fn compress(
    input: []const u8,
    output: []u8,
    table: block_table.BlockTable,
) !SnappyError!usize {
    if (input.len == 0) return SnappyError.EmptyInput;

    std.mem.writeInt(u16, output[0..2], @intCast(input.len), std.builtin.Endian.little);
    var cursor: usize = 0;
    var d: usize = 2;

    while (cursor < input.len) {
        const block_size = if (cursor + block.MAX_BLOCK_SIZE > input.len) input.len - cursor else block.MAX_BLOCK_SIZE;

        var blk = block.new_block(input[cursor..block_size], output.ptr, d);
        block.compress(&blk, table);

        cursor += block_size;
        d += blk.dest_cursor;
    }

    return d;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const src = "nazar Hussain abnzar shud adfds asdf adfdasf dasf das fdas f dasfdasfads adsf adsfasf asdfdasf";

    const max_len = try max_compress_len(src.len) catch |err| {
        const err_message = try std.fmt.allocPrint(allocator, "Input is too large {s}", .{@errorName(err)});
        defer allocator.free(err_message);
        @panic(err_message);
    };

    var output = try allocator.alloc(u8, max_len);
    defer allocator.free(output);

    const table = try block_table.new(output.len, allocator);
    defer table.free(allocator);

    if (try compress(src[0..], output, table)) |size| {
        std.debug.print("input: {any}\n", .{src});
        std.debug.print("output: {any}\n", .{output[0..size]});
    } else |err| {
        std.debug.print("Got error compressing: {any}", .{err});
    }
}
