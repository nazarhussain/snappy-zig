const std = @import("std");
const block_table = @import("./block_table.zig");
const bytes = @import("./bytes.zig");

const assert = std.debug.assert;

pub const MAX_BLOCK_SIZE = 65536;

const INPUT_MARGIN: usize = 16 - 1;

pub const MIN_NON_LITERAL_BLOCK_SIZE: usize = 1 + 1 + INPUT_MARGIN;

const Block = struct {
    src: []const u8,
    src_cursor: usize,
    s_limit: usize,
    dest: [*]u8,
    dest_cursor: usize,
    next_emit: usize,
};

pub fn new_block(src: []const u8, dst: [*]u8, d: usize) Block {
    return Block{
        .src = src,
        .src_cursor = 0,
        .s_limit = src.len,
        .dest = dst,
        .dest_cursor = d,
        .next_emit = 0,
    };
}

pub fn compress(self: *Block, table: block_table.BlockTable) void {
    assert(self.src.len >= MIN_NON_LITERAL_BLOCK_SIZE);

    self.src_cursor += 1;
    self.s_limit -= INPUT_MARGIN;

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

            if (s_next > self.s_limit) {
                return done(self);
            }

            {
                candidate = table.get(next_hash);
                table.set(next_hash, @intCast(self.src_cursor));

                const x = bytes.load_32(self.src, s_next);
                next_hash = table.hash(x);

                const cur = bytes.load_32(self.src, self.src_cursor);
                const cand = bytes.load_32(self.src, candidate);

                if (cur == cand) {
                    break;
                }
            }
        }

        const lit_end = self.src_cursor;

        emit_literal(self, lit_end);

        while (true) {
            const base = self.src_cursor;
            self.src_cursor += 4;

            candidate = extend_match(self, candidate + 4);

            if (base < candidate) {
                return done(self);
            }

            const offset = base - candidate;
            var len = self.src_cursor - base;

            {
                len = emit_copy(self, offset, len);
            }

            self.next_emit = self.src_cursor;

            if (self.src_cursor >= self.s_limit) {
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

const Tag = enum(u8) {
    Literal = 0b00,
    Copy1 = 0b01,
    Copy2 = 0b10,
    // Compression never actually emits a Copy4 operation and decompression
    // uses tricks so that we never explicitly do case analysis on the copy
    // operation type, therefore leading to the fact that we never use Copy4.
    Copy4 = 0b11,
};

fn emit_literal(self: *Block, lit_end: usize) void {
    const lit_start = self.next_emit;
    const len = lit_end - lit_start;
    const n: u8 = @as(u8, @intCast(len)) - 1;
    if (n <= 59) {
        self.dest[self.dest_cursor] = (n << 2) | @intFromEnum(Tag.Literal);
        self.dest_cursor += 1;
        if (len <= 16 and lit_start + 16 <= self.src.len) {
            @memcpy(self.dest[self.dest_cursor..(self.dest_cursor + 16)], self.src[lit_start..(lit_start + 16)]);
            self.dest_cursor += len;
            return;
        }
    } else if (n < 256) {
        self.dest[self.dest_cursor] = (60 << 2) | @intFromEnum(Tag.Literal);
        self.dest[self.dest_cursor + 1] = n;
        self.dest_cursor += 2;
    } else {
        self.dest[self.dest_cursor] = (61 << 2) | (Tag.Literal);
        bytes.write_u16_le(n, self.dest[self.dest_cursor..]);
        self.dest_cursor += 3;
    }

    @memcpy(self.dest[self.dest_cursor..(self.dest_cursor + len)], self.src[lit_start..(lit_start + len)]);
    self.dest_cursor += len;
}

fn extend_match(self: *Block, cand_: usize) usize {
    assert(cand_ < self.src_cursor);
    var cand = cand_;

    while (self.src_cursor + 8 <= self.src.len) {
        const x = bytes.load_32(self.src, self.src_cursor);
        const y = bytes.load_32(self.src, cand);
        if (x == y) {
            self.src_cursor += 8;
            cand += 8;
        } else {
            const z = x ^ y;
            self.src_cursor += bytes.trailing_zerors(z) / 8;
            return cand;
        }
    }
    // When we have fewer than 8 bytes left in the block, fall back to the
    // slow loop.
    while (self.src_cursor < self.src.len and self.src[self.src_cursor] == self.src[cand]) {
        self.src_cursor += 1;
        cand += 1;
    }

    return cand;
}

fn emit_copy(self: *Block, offset: usize, len_: usize) usize {
    var len = len_;

    assert(1 <= offset and offset <= 65535);
    // Copy operations only allow lengths up to 64, but we'll allow bigger
    // lengths and emit as many operations as we need.
    //
    // N.B. Since our block size is 64KB, we never actually emit a copy 4
    // operation.
    assert(4 <= len and len <= 65535);

    // Emit copy 2 operations until we don't have to.
    // We check on 68 here and emit a shorter copy than 64 below because
    // it is cheaper to, e.g., encode a length 67 copy as a length 60
    // copy 2 followed by a length 7 copy 1 than to encode it as a length
    // 64 copy 2 followed by a length 3 copy 2. They key here is that a
    // copy 1 operation requires at least length 4 which forces a length 3
    // copy to use a copy 2 operation.
    while (len >= 68) {
        emit_copy2(self, offset, 64);
        len -= 64;
    }
    if (len > 64) {
        emit_copy2(self, offset, 60);
        len -= 60;
    }
    // If we can squeeze the last copy into a copy 1 operation, do it.
    if (len <= 11 and offset <= 2047) {
        self.dest[self.dest_cursor] = @intCast(((offset >> 8) << 5) | ((len - 4) << 2) | @intFromEnum(Tag.Copy1));
        self.dest[self.dest_cursor + 1] = @intCast(offset);
        self.dest_cursor += 2;
    } else {
        emit_copy2(self, offset, len);
    }

    return len;
}

fn emit_copy2(self: *Block, offset: usize, len: usize) void {
    assert(1 <= offset and offset <= 65535);
    assert(1 <= len and len <= 64);

    self.dest[self.dest_cursor] = @intCast((len - 1) << 2 | @intFromEnum(Tag.Copy2));
    bytes.write_u16_le(@intCast(offset), self.dest[self.dest_cursor + 1 ..]);
    self.dest_cursor += 3;
}
