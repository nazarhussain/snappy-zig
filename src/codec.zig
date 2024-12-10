const std = @import("std");
const block = @import("./block.zig");
const block_table = @import("./block_table.zig");
const bytes = @import("./bytes.zig");

const assert = std.debug.assert;
const mem = std.mem;

const MAX_INPUT_SIZE = std.math.maxInt(u32);
const STREAM_BODY = "sNaPpY";

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

const SnappyError = error{ EmptyInput, LargeInput, SmallOutputBuffer, Encoding, OutOfMemory, Overflow };

pub const Codecs = struct {
    Encoder: SnappyEncoder,
};

pub const standard = Codecs{
    .Encoder = SnappyEncoder.init(gpa.allocator()),
};

pub const SnappyEncoder = struct {
    allocator: mem.Allocator,
    additional_bytes: usize,

    /// A bunch of assertions, then simply pass the data right through.
    pub fn init(allocator: mem.Allocator) SnappyEncoder {
        return SnappyEncoder{ .allocator = allocator, .additional_bytes = 32 };
    }

    /// Compute the encoded length
    pub fn calcSize(encoder: *const SnappyEncoder, source_len: usize) usize {
        return encoder.additional_bytes + source_len + (source_len / 6);
    }

    // dest must be compatible with std.io.Writer's writeAll interface
    pub fn encodeWriter(encoder: *const SnappyEncoder, dest: anytype, source: []const u8) SnappyError!void {
        if (source.len == 0) {
            try dest.writeAll("");
            return;
        }

        const max_len = encoder.calcSize(source.len);
        if (max_len > MAX_INPUT_SIZE) return SnappyError.LargeInput;
        // if (dest.len < max_len) return SnappyError.SmallOutputBuffer;

        const table = try block_table.new(max_len, encoder.allocator);
        defer table.free(encoder.allocator);

        var chunker = mem.window(u8, source, 3, 3);
        while (chunker.next()) |chunk| {
            var temp: [5]u8 = undefined;
            const s = try encoder.encode(&temp, chunk);
            try dest.writeAll(s);
        }
    }

    pub fn encode(encoder: *const SnappyEncoder, dest: []u8, source: []const u8) SnappyError![]const u8 {
        if (source.len == 0) return "";

        const max_len = encoder.calcSize(source.len);
        if (max_len > MAX_INPUT_SIZE) return SnappyError.LargeInput;
        if (dest.len < max_len) return SnappyError.SmallOutputBuffer;

        const table = try block_table.new(max_len, encoder.allocator);
        defer table.free(encoder.allocator);

        if (try compress(source, dest, table)) |size| {
            return dest[0..size];
        } else |_| {
            return SnappyError.Encoding;
        }
    }
};

pub fn compress(
    input: []const u8,
    output: []u8,
    table: block_table.BlockTable,
) !SnappyError!usize {
    if (input.len == 0) return SnappyError.EmptyInput;

    var d = bytes.write_varint(input.len, output, 0);
    var cursor: usize = 0;

    while (cursor < input.len) {
        const block_size = @min((input.len - cursor), block.MAX_BLOCK_SIZE);

        var blk = block.new_block(input[cursor..block_size], output.ptr, d);
        block.compress(&blk, table);

        cursor += block_size;
        d += blk.dest_cursor;
    }

    return d - 1;
}
