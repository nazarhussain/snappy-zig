const std = @import("std");
const snappy = @import("./codec.zig");
// const libSnappy = @import("./snappy_cpp.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const src = "neighbouring pool--she could hear the rattle of the teacups as";

    const max_len = snappy.standard.Encoder.calcSize(src.len);
    const output = try allocator.alloc(u8, max_len);
    defer allocator.free(output);

    const encoded = snappy.standard.Encoder.encode(output, src);
    // libSnappy.snappy_compress(input: [*c]const u8, input_length: usize, compressed: [*c]u8, compressed_length: [*c]usize);

    std.debug.print("input: {any}\n", .{src});
    std.debug.print("output: {any}\n", .{encoded});
}
