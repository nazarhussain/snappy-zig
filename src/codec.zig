const std = @import("std");
const block = @import("./block.zig");
const block_table = @import("./block_table.zig");
const bytes = @import("./bytes.zig");

const assert = std.debug.assert;
const mem = std.mem;

const MAX_INPUT_SIZE = std.math.maxInt(u32);
const STREAM_BODY = "sNaPpY";

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

const SnappyError = error{ LargeInput, SmallOutputBuffer, Encoding, OutOfMemory, Overflow };

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

        // TODO: Debug this case with a streaming writer
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
        const max_len = encoder.calcSize(source.len);
        if (max_len > MAX_INPUT_SIZE) return SnappyError.LargeInput;
        if (dest.len < max_len) return SnappyError.SmallOutputBuffer;

        if (try compress(source, dest, encoder.allocator)) |size| {
            return dest[0..size];
        } else |_| {
            return SnappyError.Encoding;
        }
    }
};

pub fn compress(
    input: []const u8,
    output: []u8,
    allocator: std.mem.Allocator,
) !SnappyError!usize {
    if (input.len == 0) {
        // Set the first byte as the size of the input
        output[0] = 0;

        // Return the size of the output
        return 1;
    }

    var dest_cursor = bytes.writeVarint(input.len, output, 0);
    var src_cursor: usize = 0;

    while (src_cursor < input.len) {
        const block_size = @min((input.len - src_cursor), block.MAX_BLOCK_SIZE);
        var blk = block.new_block(input[src_cursor..][0..block_size], output.ptr, dest_cursor);

        if (blk.src.len < block.MIN_NON_LITERAL_BLOCK_SIZE) {
            block.emitLiteral(&blk, block_size);
        } else {
            const table = try block_table.new(blk.src.len, allocator);
            block.compress(&blk, &table);
            table.free(allocator);
        }

        src_cursor += block_size;
        dest_cursor = blk.dest_cursor;
    }

    return dest_cursor;
}

const libSnappy = @import("./lib_snappy.zig");
const testing = std.testing;

const alice29 = @embedFile("./data/alice29.txt");

test "empty string" {
    try testEncode(standard, "");
}

test "small phrase" {
    try testEncode(standard, "could");
}

test "simple phrase" {
    const data = "neighbouring pool--she could hear the rattle of the teacups as";
    try testEncode(standard, data);
}

test "simple phrase with repeated strings" {
    const data = "aaaaaaaabbbbbbbbaaaaaaaabbbbbbbb";
    try testEncode(standard, data);
}

test "simple phrase with multiple repeated strings" {
    const data = "aaaaaaaabbbbbbbbaaaaaaaabbbbbbbbaaaaaaaabbbbbbbbaaaaaaaabbbbbbbb";
    try testEncode(standard, data);
}

test "medium text" {
    const data = "Idioms are a wonderful part of the English language that gives it a lot of flavor. They force people to know more than the literal meaning of words. Idioms are commonly used phrases that have a meaning completely different than their literal meaning. This can be quite confusing to those who aren't familiar with the idiom and those who are studying English.";
    try testEncode(standard, data);
}

test "larger text" {
    try testEncode(standard, alice29);
}

fn testEncode(codecs: Codecs, data: []const u8) !void {
    const zig_compression_buffer = try testing.allocator.alloc(u8, codecs.Encoder.calcSize(data.len));
    defer testing.allocator.free(zig_compression_buffer);
    const compressed_by_zig = try codecs.Encoder.encode(zig_compression_buffer, data);

    // var c_compression_buffer = try testing.allocator.alloc(u8, libSnappy.snappy_max_compressed_length(data.len));
    // defer testing.allocator.free(c_compression_buffer);
    // var compressed_length: usize = undefined;
    // _ = libSnappy.snappy_compress(data.ptr, data.len, c_compression_buffer.ptr, &compressed_length);
    // const compressed_by_c = c_compression_buffer[0..compressed_length];

    var c_uncompress_buffer = try testing.allocator.alloc(u8, data.len);
    defer testing.allocator.free(c_uncompress_buffer);
    var c_uncompress_len: usize = undefined;
    _ = libSnappy.snappy_uncompress(compressed_by_zig.ptr, compressed_by_zig.len, c_uncompress_buffer.ptr, &c_uncompress_len);
    const uncompressed_by_c = c_uncompress_buffer[0..data.len];

    // try testing.expectEqualSlices(u8, compressed_by_c, compressed_by_zig);
    try testing.expectEqualSlices(u8, uncompressed_by_c, data);
}
