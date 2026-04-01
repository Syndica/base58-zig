const std = @import("std");
const builtin = @import("builtin");

/// Return maximum encoded length based on the decoded length, approximately.
/// This is based on the base conversion ratio `log2(256) / log2(58)` being roughly equal to `1.37`.
pub fn encodedMaxSize(decoded_len: usize) usize {
    if (decoded_len == 0) return 0;
    return decoded_len + (decoded_len * 37) / 100 + 1;
}

/// Return maximum encoded length based on the decoded length, approximately.
/// This is based on the base conversion ratio `log2(58) / log2(256)` being roughly equal to `0.74`.
pub fn decodedMaxSize(encoded_len: usize) usize {
    if (encoded_len == 0) return 0;
    return (encoded_len * 74) / 100 + 1;
}

pub const Table = struct {
    alphabet: [58]u7,
    decode_table: [128]u8,

    pub const BITCOIN = Table.init(.{
        '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J',
        'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
        'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z',
    }) catch unreachable;

    pub const InitError = error{DuplicateCharacter};

    /// Initialize an Alpabet set with options
    pub fn init(alphabet: [58]u7) InitError!Table {
        var decode_table: [128]u8 = .{0xFF} ** 128;

        for (alphabet, 0..) |enc, i| {
            if (decode_table[enc] != 0xFF) return error.DuplicateCharacter;
            decode_table[enc] = @intCast(i);
        }

        return .{
            .alphabet = alphabet,
            .decode_table = decode_table,
        };
    }

    /// Count Leading Zeros in an encoded string.
    /// Defined for any input, regardless of whether it is a well-formed base58-encoded string.
    ///
    /// Returns `0` for an empty string.
    /// Returns `encoded.len` for a string that consists entirely of base58 "zero" characters.
    pub fn encodedClz(self: Table, encoded: []const u8) usize {
        return indexOfNotScalarPos(u8, encoded, 0, self.alphabet[0]) orelse encoded.len;
    }

    /// Returns the index of the first non-leading-zero in `encoded`.
    /// This can be used to trim leading zeros from `encoded`, as in `encoded[self.encodedTrimLeadingZeros(encoded)..]`.
    ///
    /// Returns `0` for an empty string.
    /// Returns `encoded.len - 1` for a base58 string consisting entirely of base58 "zero" characters,
    /// such that the trimmed string becomes a single zero.
    pub fn encodedTrimLeadingZeros(self: Table, encoded: []const u8) usize {
        const lzc = self.encodedClz(encoded);
        return lzc -| @intFromBool(lzc == encoded.len);
    }

    /// Count Leading Zeros in a decoded string.
    ///
    /// Returns `0` for an empty string.
    /// Returns `decoded.len` for a string that consists entirely of bytes of value zero.
    pub fn decodedClz(decoded: []const u8) usize {
        return indexOfNotScalarPos(u8, decoded, 0, 0) orelse decoded.len;
    }

    /// Returns the index of the first non-leading-zero in `decoded`.
    /// This can be used to trim leading zeros from `decoded`, as in `decoded[decodedTrimLeadingZeros(decoded)..]`.
    ///
    /// Returns `0` for an empty string.
    /// Returns `decoded.len - 1` for a string consisting entirely of bytes of value zero,
    /// such that the trimmed string becomes a single zero.
    pub fn decodedTrimLeadingZeros(decoded: []const u8) usize {
        const lzc = decodedClz(decoded);
        return lzc -| @intFromBool(lzc == decoded.len);
    }

    /// Asserts `decodedMaxSize(encoded.len) >= decoded.len`.
    /// Returns `start`; the encoded string is written to `encoded[start..]`,
    /// with all of `encoded[0..start]` being set to leading zeros.
    pub fn encodePadded(self: Table, encoded: []u8, decoded: []const u8) usize {
        std.debug.assert(decodedMaxSize(encoded.len) >= decoded.len);

        const plus_mul_max = std.math.maxInt(u8) + std.math.maxInt(u8) * 256;
        const PlusMul = std.math.IntFittingRange(0, plus_mul_max);
        const Carry = std.math.IntFittingRange(0, plus_mul_max / 58);

        var index: usize = 0;
        for (decoded) |byte| {
            var carry: Carry = byte;

            for (0..index) |prev_index| {
                const plus_mul = carry + encoded[encoded.len - 1 - prev_index] * @as(PlusMul, 256);
                encoded[encoded.len - 1 - prev_index] = @intCast(plus_mul % 58);
                carry = @intCast(plus_mul / 58);
            }

            while (carry > 0) {
                encoded[encoded.len - 1 - index] = @intCast(carry % 58);
                index += 1;
                carry /= 58;
            }
        }

        for (decoded) |byte| {
            if (byte != 0) break;
            encoded[encoded.len - 1 - index] = 0;
            index += 1;
        }

        @memset(encoded[0 .. encoded.len - index], self.alphabet[0]);
        for (0..index) |prev_index| {
            const byte = &encoded[encoded.len - 1 - prev_index];
            byte.* = self.alphabet[byte.*];
        }
        return encoded.len - index;
    }

    /// Asserts `decodedMaxSize(encoded.len) >= decoded.len`.
    pub fn encode(self: Table, encoded: []u8, decoded: []const u8) usize {
        const start = self.encodePadded(encoded, decoded);
        const len = encoded.len - start;
        std.mem.copyForwards(u8, encoded[0..len], encoded[start..]);
        return len;
    }

    pub const DecodeError = error{
        NonAsciiCharacter,
        InvalidCharacter,
    };

    /// Asserts `encodedMaxSize(decoded.len) >= encoded.len`.
    pub fn decode(self: Table, decoded: []u8, encoded: []const u8) DecodeError!usize {
        std.debug.assert(encodedMaxSize(decoded.len) >= encoded.len);

        const plus_mul_max = 127 + 255 * 58; // maximum value of `value`, plus the maximum value of `dest[prev_index]` times 58
        const PlusMul = std.math.IntFittingRange(0, plus_mul_max);
        const plus_mul_shr8_max = plus_mul_max >> 8; // maximum value of shifting `plus_mul` right by 8 bits
        comptime std.debug.assert(plus_mul_shr8_max <= std.math.maxInt(u8));

        var index: usize = 0;
        for (encoded) |char| {
            if (char > 127) return error.NonAsciiCharacter;

            var value: u8 = self.decode_table[char];
            if (value == 0xFF) return error.InvalidCharacter;
            for (0..index) |prev_index| {
                const plus_mul = value + @as(PlusMul, decoded[decoded.len - 1 - prev_index]) * 58;
                decoded[decoded.len - 1 - prev_index] = @truncate(plus_mul);
                value = @intCast(plus_mul >> 8);
            }

            // this was a `while (value > 0) { ...; value >>= 8; }`, but
            // but `value` only has 8 bits, meaning it would run exactly once.
            if (value > 0) {
                decoded[decoded.len - 1 - index] = value;
                index += 1;
            }
        }

        const zero = self.alphabet[0];
        for (encoded) |c| {
            if (c != zero) break;
            if (index == decoded.len) break;
            decoded[decoded.len - 1 - index] = 0;
            index += 1;
        }
        std.mem.copyForwards(u8, decoded[0..index], decoded[decoded.len - index ..][0..index]);

        return index;
    }
};

/// NOTE: see `std.mem.indexOfScalarPos`, and the equivalent private declaration in `std.mem`.
const use_vectors = switch (builtin.zig_backend) {
    // These backends don't support vectors yet.
    .stage2_aarch64,
    .stage2_powerpc,
    .stage2_riscv64,
    => false,
    // The SPIR-V backend does not support the optimized path yet.
    .stage2_spirv => false,
    else => true,
};

/// NOTE: see `std.mem.indexOfScalarPos`, and the equivalent private declaration in `std.mem`.
///
// The naive memory comparison implementation is more useful for fuzzers to find interesting inputs.
const use_vectors_for_comparison = use_vectors and !builtin.fuzz;

/// Inverse of `std.mem.indexOfScalarPos`, returning the index
/// of the first element which is not equal to `value`.
fn indexOfNotScalarPos(
    comptime T: type,
    slice: []const T,
    start_index: usize,
    value: T,
) ?usize {
    if (start_index >= slice.len) return null;

    var i: usize = start_index;

    if (use_vectors_for_comparison and
        !std.debug.inValgrind() and // https://github.com/ziglang/zig/issues/17717
        !@inComptime() and
        (@typeInfo(T) == .int or @typeInfo(T) == .float) and std.math.isPowerOfTwo(@bitSizeOf(T)))
    {
        if (std.simd.suggestVectorLength(T)) |block_len| {
            // For Intel Nehalem (2009) and AMD Bulldozer (2012) or later, unaligned loads on aligned data result
            // in the same execution as aligned loads. We ignore older arch's here and don't bother pre-aligning.
            //
            // Use `std.simd.suggestVectorLength(T)` to get the same alignment as used in this function
            // however this usually isn't necessary unless your arch has a performance penalty due to this.
            //
            // This may differ for other arch's. Arm for example costs a cycle when loading across a cache
            // line so explicit alignment prologues may be worth exploration.

            // Unrolling here is ~10% improvement. We can then do one bounds check every 2 blocks
            // instead of one which adds up.
            const Block = @Vector(block_len, T);
            if (i + 2 * block_len < slice.len) {
                const mask: Block = @splat(value);
                while (true) {
                    inline for (0..2) |_| {
                        const block: Block = slice[i..][0..block_len].*;
                        const matches = block != mask; // NOTE(ours): inverted condition
                        if (@reduce(.Or, matches)) {
                            return i + std.simd.firstTrue(matches).?;
                        }
                        i += block_len;
                    }
                    if (i + 2 * block_len >= slice.len) break;
                }
            }

            // {block_len, block_len / 2} check
            inline for (0..2) |j| {
                const block_x_len = block_len / (1 << j);
                comptime if (block_x_len < 4) break;

                const BlockX = @Vector(block_x_len, T);
                if (i + block_x_len < slice.len) {
                    const mask: BlockX = @splat(value);
                    const block: BlockX = slice[i..][0..block_x_len].*;
                    const matches = block != mask; // NOTE(ours): inverted condition
                    if (@reduce(.Or, matches)) {
                        return i + std.simd.firstTrue(matches).?;
                    }
                    i += block_x_len;
                }
            }
        }
    }

    for (slice[i..], i..) |c, j| {
        if (c != value) return j; // NOTE(ours): inverted condition
    }
    return null;
}

fn testRoundTripFromDecoded(
    table: Table,
    decoded_input: []const u8,
    maybe_expect_encoded: ?[]const u8,
) !void {
    const gpa = std.testing.allocator;

    const encoded_data = try gpa.alloc(u8, encodedMaxSize(decoded_input.len));
    defer gpa.free(encoded_data);
    _ = table.encodePadded(encoded_data, decoded_input);
    const encoded_data_trimmed = encoded_data[table.encodedTrimLeadingZeros(encoded_data)..];

    if (maybe_expect_encoded) |expect_encoded| {
        try std.testing.expectEqualStrings(expect_encoded, encoded_data_trimmed);
    }

    const decoded_buffer = try gpa.alloc(u8, decoded_input.len);
    defer gpa.free(decoded_buffer);
    const decoded_data = decoded_buffer[0..try table.decode(decoded_buffer, encoded_data)];

    try std.testing.expectEqualSlices(u8, decoded_input, decoded_data);
}

fn testRoundTripFromEncoded(
    table: Table,
    encoded_input: []const u8,
    maybe_expect_decoded: ?[]const u8,
) !void {
    const gpa = std.testing.allocator;

    const decoded_buffer = try gpa.alloc(u8, decodedMaxSize(encoded_input.len));
    defer gpa.free(decoded_buffer);
    const decoded_data = decoded_buffer[0..try table.decode(decoded_buffer, encoded_input)];

    if (maybe_expect_decoded) |expect_decoded| {
        try std.testing.expectEqualSlices(
            u8,
            expect_decoded[Table.decodedTrimLeadingZeros(expect_decoded)..],
            decoded_data[Table.decodedTrimLeadingZeros(decoded_data)..],
        );
    }

    const encoded_data = try gpa.alloc(u8, encoded_input.len);
    defer gpa.free(encoded_data);
    _ = table.encodePadded(encoded_data, decoded_data);

    try std.testing.expectEqualSlices(u8, encoded_input, encoded_data);
}

test "Hello, World" {
    try testRoundTripFromDecoded(.BITCOIN, "Hello, World", null);
}

test "encode/decode values correctly" {
    const encoded_4rL4R = "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa";
    const decoded_4rL4R: [32]u8 = .{
        57,  54,  18,  6,   106, 202, 13,  245, 224, 235, 33,  252, 254,
        251, 161, 17,  248, 108, 25,  214, 169, 154, 91,  101, 17,  121,
        235, 82,  175, 197, 144, 145,
    };
    try testRoundTripFromDecoded(.BITCOIN, &decoded_4rL4R, encoded_4rL4R);
    try testRoundTripFromEncoded(.BITCOIN, encoded_4rL4R, &decoded_4rL4R);
}

test "handle leading 0s slice" {
    try testRoundTripFromDecoded(.BITCOIN, &.{ 0, 0, 13, 4, 5, 6, 3, 23, 64, 75 }, null);
}

test "handle single byte slice" {
    try testRoundTripFromDecoded(.BITCOIN, &.{255}, null);
}

test "various slice sizes" {
    var prng_state: std.Random.DefaultPrng = .init(13773);
    const prng = prng_state.random();
    var buffer: [500 * 133]u8 = undefined;
    for (0..500) |i| {
        const original_data = buffer[0..i];
        prng.bytes(original_data);
        try testRoundTripFromDecoded(.BITCOIN, original_data, null);
    }
}

test "big slice" {
    var prng_state: std.Random.DefaultPrng = .init(24830);
    const prng = prng_state.random();
    var data: [10_000]u8 = undefined;
    prng.bytes(&data);
    try testRoundTripFromDecoded(.BITCOIN, &data, null);
}

test "decode with leading zeros" {
    const encoded_1111 = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111112";
    try testRoundTripFromEncoded(.BITCOIN, encoded_1111, &.{1});
}

test "decode all leading zeros" {
    const encoded_1111 = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    try testRoundTripFromEncoded(.BITCOIN, encoded_1111, &.{0});
}
