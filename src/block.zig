const std = @import("std");
const block_table = @import("./block_table.zig");
const bytes = @import("./bytes.zig");

const assert = std.debug.assert;
const testing = std.testing;

const kb32 = 1024 * 32;

// 32kb block size
// https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/format_description.txt#L79
pub const MAX_BLOCK_SIZE = kb32;

const INPUT_MARGIN: usize = 16 - 1;

pub const MIN_NON_LITERAL_BLOCK_SIZE: usize = 1 + 1 + INPUT_MARGIN;

const Tag = enum(u8) {
    Literal = 0b00,
    Copy1 = 0b01,
    Copy2 = 0b10,
    // Compression never actually emits a Copy4 operation and decompression
    // uses tricks so that we never explicitly do case analysis on the copy
    // operation type, therefore leading to the fact that we never use Copy4.
    Copy4 = 0b11,
};

test "tag literal" {
    try testing.expectEqual(@intFromEnum(Tag.Literal), 0b00);
}
test "tag copy1" {
    try testing.expectEqual(@intFromEnum(Tag.Copy1), 0b01);
}

test "tag copy2" {
    try testing.expectEqual(@intFromEnum(Tag.Copy2), 0b10);
}

test "tag copy4" {
    try testing.expectEqual(@intFromEnum(Tag.Copy4), 0b11);
}

const Block = struct {
    src: []const u8,
    src_cursor: usize,
    src_limit: usize,
    dest: [*]u8,
    dest_cursor: usize,
    next_emit: usize,
};

pub fn new_block(src: []const u8, dst: [*]u8, d: usize) Block {
    return Block{
        .src = src,
        .src_cursor = 0,
        .src_limit = src.len,
        .dest = dst,
        .dest_cursor = d,
        .next_emit = 0,
    };
}

pub fn compress(self: *Block, table: block_table.BlockTable) void {
    if (self.src.len < MIN_NON_LITERAL_BLOCK_SIZE) {
        emit_literal(self, self.src.len);
        self.dest_cursor += self.src.len;
        return;
    }

    self.src_cursor += 1;
    self.src_limit -= INPUT_MARGIN;

    var next_hash =
        table.hash(bytes.load_32(self.src, self.src_cursor));

    while (true) {
        var skip: usize = 32;
        var candidate: usize = 0;
        var s_next = self.src_cursor;

        while (true) {
            self.src_cursor = s_next;
            const bytes_between_hash_lookups = skip >> 5;
            s_next = self.src_cursor + bytes_between_hash_lookups;
            skip += bytes_between_hash_lookups;

            if (s_next > self.src_limit) {
                return done(self);
            }

            {
                candidate = table.get(next_hash);
                table.set(next_hash, @intCast(self.src_cursor));

                const x = bytes.load_32(self.src, s_next);
                next_hash = table.hash(x);

                const cur = bytes.load_32(self.src, self.src_cursor);
                const next_candidate = bytes.load_32(self.src, candidate);

                if (cur == next_candidate) {
                    break;
                }
            }
        }

        const lit_end = self.src_cursor;

        emit_literal(self, lit_end);

        while (true) {
            const base = self.src_cursor;
            self.src_cursor += 4;

            {
                candidate = extend_match(self, candidate + 4);
            }

            // if (base < candidate) {
            //     return done(self);
            // }

            const offset = base - candidate;
            var len = self.src_cursor - base;
            len = emit_copy(self, offset, len);

            self.next_emit = self.src_cursor;

            if (self.src_cursor >= self.src_limit) {
                return done(self);
            }

            {
                const x = bytes.load_32(self.src, (self.src_cursor - 1));
                const prev_hash = table.hash(x);
                table.set(prev_hash, @intCast(self.src_cursor - 1));
                const cur_hash = table.hash((x >> 8));

                candidate = table.get(cur_hash);
                table.set(cur_hash, @intCast(self.src_cursor));
                const y = bytes.load_32(self.src, candidate);

                if ((x >> 8) != y) {
                    next_hash = table.hash(x >> 16);
                    self.src_cursor += 1;
                    break;
                }
            }
        }
    }
}

fn done(self: *Block) void {
    if (self.next_emit < self.src.len) {
        const lit_end = self.src.len;
        emit_literal(self, lit_end);
    }
}

/// Literals are uncompressed data stored directly in the byte stream.
/// https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/format_description.txt#L48
fn emit_literal(self: *Block, lit_end: usize) void {
    std.debug.print("\n{any}, cursor:{}, lit_end:{}\n", .{ self.dest[0..self.dest_cursor], self.dest_cursor, lit_end });
    const lit_start = self.next_emit;
    const len = lit_end - lit_start;
    const len_1: u8 = @as(u8, @intCast(len)) - 1;

    // For literals up to and including 60 bytes in length, the upper
    // six bits of the tag byte contain (len-1). The literal follows
    // immediately thereafter in the byte stream.
    if (len <= 60) {
        self.dest[self.dest_cursor] = (len_1 << 2) | @intFromEnum(Tag.Literal);
        self.dest_cursor += 1;
    }
    // For longer literals, the (len-1) value is stored after the tag byte,
    // little-endian. The upper six bits of the tag byte describe how
    // many bytes are used for the length; 60, 61, 62 or 63 for
    // 1-4 bytes, respectively. The literal itself follows after the
    // length.
    else {
        const length_byte_size = bytes.get_byte_size(len_1);
        self.dest[self.dest_cursor] = ((59 + length_byte_size) << 2) | @intFromEnum(Tag.Literal);
        bytes.write_16_int_le(len_1, self.dest[(self.dest_cursor + 1)..]);
        self.dest_cursor += (length_byte_size + 1);
    }

    @memcpy(self.dest[self.dest_cursor..(self.dest_cursor + len)], self.src[lit_start..lit_end]);
    self.dest_cursor += len;
}

fn emit_copy(self: *Block, offset: usize, len: usize) usize {
    // Offset can not cross the max block size
    assert(1 <= offset and offset <= MAX_BLOCK_SIZE);

    // Length can not cross the max block size
    assert(4 <= len and len <= MAX_BLOCK_SIZE);

    // These elements can encode lengths between [4..11] bytes and offsets
    // between [0..2047] bytes.
    // https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/format_description.txt#L91-L92
    if ((4 <= len and len <= 11) and (0 <= offset and offset <= 2047)) {
        emit_copy1(self, offset, len);
        return 0;
    }

    // https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/format_description.txt#L100-L101
    if ((4 <= len and len <= 64) and (0 <= offset and offset <= 65535)) {
        emit_copy2(self, offset, len);
        return 0;
    }

    // https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/format_description.txt#L108
    if ((4 <= len and len <= 64) and offset > 65535) {
        emit_copy4(self, offset, len);
        return 0;
    }

    return len;
}

fn emit_copy1(self: *Block, offset: usize, len: usize) void {
    self.dest[self.dest_cursor] = @intCast(((offset >> 8) << 5) | (len - 4) << 2 | @intFromEnum(Tag.Copy1));
    self.dest[self.dest_cursor + 1] = @intCast(offset & 0xFF);
    self.dest_cursor += 2;
}

fn emit_copy2(self: *Block, offset: usize, len: usize) void {
    self.dest[self.dest_cursor] = @intCast((len - 1) << 2 | @intFromEnum(Tag.Copy2));
    bytes.write_16_int_le(offset, self.dest[(self.dest_cursor + 1)..][0..]);
    self.dest_cursor += 3;
}

fn emit_copy4(self: *Block, offset: usize, len: usize) void {
    self.dest[self.dest_cursor] = @intCast((len - 1) << 2 | @intFromEnum(Tag.Copy2));
    bytes.write_32_int_le(offset, self.dest[(self.dest_cursor + 1)..][0..]);
    self.dest_cursor += 5;
}

fn extend_match(self: *Block, candidate_: usize) usize {
    assert(candidate_ < self.src_cursor);
    var candidate = candidate_;

    while (self.src_cursor + 8 <= self.src.len) {
        const x = bytes.load_32(self.src, self.src_cursor);
        const y = bytes.load_32(self.src, candidate);
        if (x == y) {
            self.src_cursor += 8;
            candidate += 8;
        } else {
            const z = x ^ y;
            self.src_cursor += bytes.trailing_zeros(z) / 8;
            return candidate;
        }
    }
    // When we have fewer than 8 bytes left in the block, fall back to the
    // slow loop.
    while (self.src_cursor < self.src.len and self.src[self.src_cursor] == self.src[candidate]) {
        self.src_cursor += 1;
        candidate += 1;
    }

    return candidate;
}
