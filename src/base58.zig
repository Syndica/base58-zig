const std = @import("std");

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

    /// Asserts `encoded.len >= encodedMaxSize(encoded.len)`.
    pub fn encode(self: Table, encoded: []u8, decoded: []const u8) usize {
        std.debug.assert(encoded.len >= encodedMaxSize(decoded.len));

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

        for (0..index) |prev_index| {
            const byte = &encoded[encoded.len - 1 - prev_index];
            byte.* = self.alphabet[byte.*];
        }
        std.mem.copyForwards(u8, encoded[0..index], encoded[encoded.len - index ..][0..index]);

        return index;
    }

    pub const DecodeError = error{
        NonAsciiCharacter,
        InvalidCharacter,
    };

    /// Asserts `decoded.len >= decodedMaxSize(encoded.len)`.
    pub fn decode(self: Table, decoded: []u8, encoded: []const u8) DecodeError!usize {
        std.debug.assert(decoded.len >= decodedMaxSize(encoded.len));

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
            decoded[decoded.len - 1 - index] = 0;
            index += 1;
        }
        std.mem.copyForwards(u8, decoded[0..index], decoded[decoded.len - index ..][0..index]);

        return index;
    }
};

fn testRoundTripFromDecoded(
    table: Table,
    decoded_input: []const u8,
    maybe_expect_encoded: ?[]const u8,
) !void {
    const gpa = std.testing.allocator;

    const encoded_buffer = try gpa.alloc(u8, encodedMaxSize(decoded_input.len));
    defer gpa.free(encoded_buffer);
    const encoded_data = encoded_buffer[0..table.encode(encoded_buffer, decoded_input)];

    if (maybe_expect_encoded) |expect_encoded| {
        try std.testing.expectEqualStrings(expect_encoded, encoded_data);
    }

    const decoded_buffer = try gpa.alloc(u8, decodedMaxSize(encoded_data.len));
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
        try std.testing.expectEqualStrings(expect_decoded, decoded_data);
    }

    const encoded_buffer = try gpa.alloc(u8, encodedMaxSize(decoded_data.len));
    defer gpa.free(encoded_buffer);
    const encoded_data = encoded_buffer[0..table.encode(encoded_buffer, decoded_data)];

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
