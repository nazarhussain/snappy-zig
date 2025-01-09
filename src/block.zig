const std = @import("std");
const block_table = @import("./block_table.zig");
const bytes = @import("./bytes.zig");
const print = std.debug.print;

const assert = std.debug.assert;
const testing = std.testing;

fn kb(val: comptime_int) comptime_int {
    return 1024 * val;
}

// https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/format_description.txt#L79
pub const MAX_BLOCK_SIZE = kb(32);

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

pub fn new_block(src: []const u8, dst: [*]u8, dest_cursor: usize) Block {
    return Block{ .src = src, .src_cursor = 0, .src_limit = src.len, .dest = dst, .dest_cursor = dest_cursor, .next_emit = 0 };
}

//--------------------------------------------------------------------
// Public Entry Point: Compress
//--------------------------------------------------------------------
pub fn compress(self: *Block, table: *const block_table.BlockTable) void {
    // If the data is too small, just emit it as a literal.
    if (self.src.len < MIN_NON_LITERAL_BLOCK_SIZE) {
        emitLiteral(self, self.src.len);
        return;
    }

    // Adjust these to avoid out-of-bounds issues later.
    self.src_cursor += 1;
    self.src_limit -= INPUT_MARGIN;

    // Compute the initial hash
    var next_hash = table.hash(bytes.read4BytesLE(self.src, self.src_cursor));

    // Main compression loop
    while (true) {
        var skip_distance: usize = 32;
        var candidate_index: usize = 0;
        var potential_cursor = self.src_cursor;
        // print("run: \n{any}\n\n", .{std.fmt.fmtSliceHexLower(self.dest[0..self.dest_cursor])});

        // 1) Attempt to skip until we find a match. If we run out of data, we’re done.
        while (true) {
            self.src_cursor = potential_cursor;
            // Move further in source by skipDistance / 32
            const skip_inc = skip_distance >> 5;
            potential_cursor = self.src_cursor + skip_inc;
            skip_distance += skip_inc;

            // If we’ve passed the limit, we have no more matches.
            if (potential_cursor > self.src_limit) {
                return finishBlock(self);
            }

            // Grab and update the candidate in the hash table
            candidate_index = table.get(next_hash);
            table.set(next_hash, @intCast(self.src_cursor));

            // Precompute hash for the next iteration
            const next_bytes = bytes.read4BytesLE(self.src, potential_cursor);
            next_hash = table.hash(next_bytes);

            // Compare the current 4 bytes with the candidate's 4 bytes
            const current4 = bytes.read4BytesLE(self.src, self.src_cursor);
            const candidate4 = bytes.read4BytesLE(self.src, candidate_index);

            if (current4 == candidate4) {
                break;
            }
        }

        // 2) We found a match. Emit any pending literal bytes before the match.
        const literal_end = self.src_cursor;
        emitLiteral(self, literal_end);

        // 3) Extend the match as far as possible, then loop back if we still have data.
        while (true) {
            const match_base = self.src_cursor;
            self.src_cursor += 4; // We already have 4 bytes matching
            extendMatch(self, candidate_index + 4);

            // Calculate offset/length, then emit copy
            const offset = match_base - candidate_index;
            const match_len = self.src_cursor - match_base;
            emitCopy(self, offset, match_len);

            // Update nextEmit pointer
            self.next_emit = self.src_cursor;

            // If we’re at or beyond the limit, end.
            if (self.src_cursor >= self.src_limit) {
                return finishBlock(self);
            }

            // Update hash table for next iteration
            // Insert the hash for the 4-byte window that ends at (src_cursor - 1).
            const prev_cursor = self.src_cursor - 1;
            const prev_bytes = bytes.read4BytesLE(self.src, prev_cursor);
            const prev_hash = table.hash(prev_bytes);
            table.set(prev_hash, @intCast(prev_cursor));

            // Shift the window and re-hash
            const cur_bytes = bytes.read4BytesLE(self.src, self.src_cursor);
            const cur_hash = table.hash(cur_bytes);

            // If the next 4 bytes don’t match, compute next_hash, move forward, and break.
            candidate_index = table.get(cur_hash);
            table.set(cur_hash, @intCast(self.src_cursor));
            const candidate_bytes = bytes.read4BytesLE(self.src, candidate_index);

            if (cur_bytes != candidate_bytes) {
                next_hash = table.hash(@intCast(bytes.read4BytesLE(self.src, self.src_cursor + 1)));
                self.src_cursor += 1;
                break;
            }
        }
    }
}

//--------------------------------------------------------------------
// Finalize the Block if we still have leftover literals
//--------------------------------------------------------------------
fn finishBlock(self: *Block) void {
    if (self.next_emit < self.src.len) {
        emitLiteral(self, self.src.len);
    }
}

//--------------------------------------------------------------------
// Emit a Literal
//--------------------------------------------------------------------
// A literal is uncompressed data stored directly in the byte stream.
// https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/format_description.txt#L48
//--------------------------------------------------------------------
fn emitLiteral(self: *Block, lit_end: usize) void {
    const lit_start = self.next_emit;
    const length = lit_end - lit_start;

    if (length == 0) {
        return;
    }

    // 1-byte literal length
    if (length <= 60) {
        const n = @as(u8, @intCast(length - 1));
        self.dest[self.dest_cursor] =
            (n << 2) | @intFromEnum(Tag.Literal);
        self.dest_cursor += 1;
    } else {
        // For larger literals, store the length after the tag
        const byte_count = bytes.getByteSize(length - 1);

        if (byte_count == 1) {
            self.dest[self.dest_cursor] = (60 << 2) | @intFromEnum(Tag.Literal);
            self.dest[self.dest_cursor + 1] = @as(u8, @intCast(length - 1));
            self.dest_cursor += 2;
        } else if (byte_count == 2) {
            self.dest[self.dest_cursor] = (61 << 2) | @intFromEnum(Tag.Literal);
            bytes.write2BytesIntLe(length - 1, self.dest[(self.dest_cursor + 1)..]);
            self.dest_cursor += 3;
        } else if (byte_count == 3) {
            self.dest[self.dest_cursor] = (62 << 2) | @intFromEnum(Tag.Literal);
            bytes.write3BytesIntLe(length - 1, self.dest[(self.dest_cursor + 1)..]);
            self.dest_cursor += 4;
        } else if (byte_count == 4) {
            self.dest[self.dest_cursor] = (63 << 2) | @intFromEnum(Tag.Literal);
            bytes.write4BytesIntLe(length - 1, self.dest[(self.dest_cursor + 1)..]);
            self.dest_cursor += 5;
        } else {
            unreachable;
        }
    }

    // Copy the literal data into the destination
    @memcpy(self.dest[self.dest_cursor..(self.dest_cursor + length)], self.src[lit_start..(lit_start + length)]);
    self.dest_cursor += length;
    // self.next_emit = lit_end; // Update next_emit
}

//--------------------------------------------------------------------
// Emit Copy Operations
//--------------------------------------------------------------------
// Distinguish among 1-byte, 2-byte, or 4-byte copy instructions.
//--------------------------------------------------------------------
fn emitCopy(self: *Block, offset: usize, len: usize) void {
    // Validate offset & length
    assert(0 <= offset and offset <= MAX_BLOCK_SIZE);
    assert(4 <= len and len <= MAX_BLOCK_SIZE);

    // If small enough, use 1-byte copy encoding
    if ((4 <= len and len <= 11) and (offset <= 2047)) {
        emitCopy1(self, offset, len);
        return;
    }

    // If up to 64-length, use 2-byte encoding (0..65535)
    if ((4 <= len and len <= 64) and (offset <= 65535)) {
        emitCopy2(self, offset, len);
        return;
    }

    // If offset > 65535, use 4-byte copy encoding
    if ((4 <= len and len <= 64) and offset > 65535) {
        emitCopy4(self, offset, len);
        return;
    }
}

// 1-byte copy encoding
fn emitCopy1(self: *Block, offset: usize, len: usize) void {
    // offset is stored in 2 bytes, but 1 byte for tag
    // [tag: (offset>>8 <<5) | (len-4) <<2 | Tag.Copy1, offset&0xFF]
    self.dest[self.dest_cursor] =
        @intCast(((offset >> 8) << 5) | ((len - 4) << 2) | @intFromEnum(Tag.Copy1));
    self.dest[self.dest_cursor + 1] = @intCast(offset & 0xFF);
    self.dest_cursor += 2;
}

// 2-byte copy encoding
fn emitCopy2(self: *Block, offset: usize, len: usize) void {
    self.dest[self.dest_cursor] = @intCast(((len - 1) << 2) | @intFromEnum(Tag.Copy2));
    bytes.write2BytesIntLe(offset, self.dest[(self.dest_cursor + 1)..][0..]);
    self.dest_cursor += 3;
}

// 4-byte copy encoding
fn emitCopy4(self: *Block, offset: usize, len: usize) void {
    // In snappy, 4-byte offset is rarely used, but we keep it for completeness
    self.dest[self.dest_cursor] = @intCast(((len - 1) << 2) | @intFromEnum(Tag.Copy2));
    bytes.write4BytesIntLe(offset, self.dest[(self.dest_cursor + 1)..][0..]);
    self.dest_cursor += 5;
}

//--------------------------------------------------------------------
// Extend an Ongoing Match
//--------------------------------------------------------------------
// Compare subsequent bytes after an initial 4-byte match.
//--------------------------------------------------------------------
fn extendMatch(self: *Block, candidate_index: usize) void {
    assert(candidate_index <= self.src_cursor);

    var candidate = candidate_index;

    // Fast loop: compare 8 bytes at a time if possible
    while (self.src_cursor + 8 <= self.src.len) {
        const x = bytes.read8BytesLE(self.src, self.src_cursor);
        const y = bytes.read8BytesLE(self.src, candidate);

        if (x == y) {
            self.src_cursor += 8;
            candidate += 8;
        } else {
            // Find how many bytes match exactly using trailing zeros
            const z = x ^ y;
            self.src_cursor += bytes.trailingZeros(z) / 8;
            return;
        }
    }

    // Slow loop for the remainder (fewer than 8 bytes left)
    while (self.src_cursor < self.src.len and self.src[self.src_cursor] == self.src[candidate]) {
        self.src_cursor += 1;
        candidate += 1;
    }
}
