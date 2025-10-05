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

    // -- alloc --

    pub fn encodeAlloc(
        self: Table,
        allocator: std.mem.Allocator,
        decoded: []const u8,
    ) std.mem.Allocator.Error![]u8 {
        var encoded = try allocator.alloc(u8, encodedMaxSize(decoded.len));
        errdefer allocator.free(encoded);
        const encoded_len = self.encode(encoded, decoded);
        if (encoded_len < encoded.len) {
            encoded = try allocator.realloc(encoded, encoded_len);
        }
        std.debug.assert(encoded_len == encoded.len);
        return encoded;
    }

    pub fn decodeAlloc(
        self: Table,
        allocator: std.mem.Allocator,
        encoded: []const u8,
    ) (DecodeError || std.mem.Allocator.Error)![]u8 {
        var decoded = try allocator.alloc(u8, decodedMaxSize(encoded.len) + 64);
        errdefer allocator.free(decoded);
        const decoded_len = try self.decode(decoded, encoded);
        if (decoded_len < decoded.len) {
            decoded = try allocator.realloc(decoded, decoded_len);
        }
        std.debug.assert(decoded_len == decoded.len);
        return decoded;
    }

    // -- bounded --

    pub fn encodeBounded(
        self: Table,
        comptime decoded_max_len: usize,
        decoded: std.BoundedArray(u8, decoded_max_len),
    ) std.BoundedArray(u8, encodedMaxSize(decoded_max_len)) {
        var encoded: std.BoundedArray(u8, encodedMaxSize(decoded_max_len)) = .{};
        const encoded_len = self.encode(encoded.unusedCapacitySlice(), decoded.constSlice());
        encoded.len += @intCast(encoded_len);
        return encoded;
    }

    pub fn decodeBounded(
        self: Table,
        comptime encoded_max_len: usize,
        encoded: std.BoundedArray(u8, encoded_max_len),
    ) DecodeError!std.BoundedArray(u8, decodedMaxSize(encoded_max_len)) {
        var decoded: std.BoundedArray(u8, decodedMaxSize(encoded_max_len)) = .{};
        const decoded_len = try self.decode(decoded.unusedCapacitySlice(), encoded.constSlice());
        decoded.len += @intCast(decoded_len);
        return decoded;
    }

    // -- array --

    pub fn encodeArray(
        self: Table,
        comptime decoded_len: usize,
        decoded: [decoded_len]u8,
    ) std.BoundedArray(u8, encodedMaxSize(decoded_len)) {
        var encoded: std.BoundedArray(u8, encodedMaxSize(decoded_len)) = .{};
        const encoded_len = self.encode(encoded.unusedCapacitySlice(), &decoded);
        encoded.len += @intCast(encoded_len);
        return encoded;
    }

    pub fn decodeArray(
        self: Table,
        comptime encoded_len: usize,
        encoded: [encoded_len]u8,
    ) std.BoundedArray(u8, decodedMaxSize(encoded_len)) {
        var decoded: std.BoundedArray(u8, decodedMaxSize(encoded_len)) = .{};
        const decoded_len = self.decode(decoded.unusedCapacitySlice(), &encoded);
        decoded.len += @intCast(decoded_len);
        return decoded;
    }

    // -- basic encode/decode --

    /// Asserts `encoded.len >= encodedUpperBound(encoded.len)`.
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

    /// Asserts `decoded.len >= decodedUpperBound(encoded.len)`.
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

test "should encodeAlloc value correctly" {
    const endec = Table.BITCOIN;

    const encoded_data = try endec.encodeAlloc(std.testing.allocator, &.{
        57,  54,  18,  6,   106, 202, 13,  245, 224, 235, 33,  252, 254,
        251, 161, 17,  248, 108, 25,  214, 169, 154, 91,  101, 17,  121,
        235, 82,  175, 197, 144, 145,
    });
    defer std.testing.allocator.free(encoded_data);

    const expected_data = "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa";
    try std.testing.expectEqualStrings(expected_data, encoded_data);
}

test "should decodeAlloc value correctly" {
    const endec = Table.BITCOIN;

    const decoded_data = try endec.decodeAlloc(
        std.testing.allocator,
        "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa",
    );
    defer std.testing.allocator.free(decoded_data);

    const expected_data: [32]u8 = .{
        57,  54,  18,  6,   106, 202, 13,  245, 224, 235, 33,  252, 254,
        251, 161, 17,  248, 108, 25,  214, 169, 154, 91,  101, 17,  121,
        235, 82,  175, 197, 144, 145,
    };
    try std.testing.expectEqualSlices(u8, &expected_data, decoded_data);
}

test "bytes encodeAlloc/decodeAlloc correctly" {
    const endec = Table.BITCOIN;

    const original_data: [12]u8 = "Hello, World".*;

    const encoded_data = try endec.encodeAlloc(std.testing.allocator, &original_data);
    defer std.testing.allocator.free(encoded_data);

    const decoded_data = try endec.decodeAlloc(std.testing.allocator, encoded_data);
    defer std.testing.allocator.free(decoded_data);

    try std.testing.expectEqualStrings(&original_data, decoded_data);
}

test "encodeAlloc leading 0s slice properly" {
    const endec = Table.BITCOIN;

    const original_data: [10]u8 = .{ 0, 0, 13, 4, 5, 6, 3, 23, 64, 75 };

    const encoded_data = try endec.encodeAlloc(std.testing.allocator, &original_data);
    defer std.testing.allocator.free(encoded_data);

    const decoded_data = try endec.decodeAlloc(std.testing.allocator, encoded_data);
    defer std.testing.allocator.free(decoded_data);

    try std.testing.expectEqualSlices(u8, &original_data, decoded_data);
}

test "should encodeAlloc single byte slice" {
    const endec = Table.BITCOIN;
    const original_data: [1]u8 = .{255};
    const encoded_data = endec.encodeArray(1, original_data);
    const decoded_data = try endec.decodeBounded(encodedMaxSize(1), encoded_data);
    try std.testing.expectEqualSlices(u8, &original_data, decoded_data.constSlice());
}

test "should encodeAlloc variable slice sizes" {
    const endec = Table.BITCOIN;

    var prng = std.Random.DefaultPrng.init(12345);
    for (0..2000) |_| {
        const original_data = generateRandomBytesArray(prng.random(), 1, 256);
        const encoded_data = endec.encodeBounded(256, original_data);
        const decoded_data = try endec.decodeBounded(encodedMaxSize(256), encoded_data);
        try std.testing.expectEqualSlices(u8, original_data.constSlice(), decoded_data.constSlice());
    }
}

test "checkAllAllocationFailures" {
    const S = struct {
        fn testFailing(allocator: std.mem.Allocator, random: std.Random) !void {
            const endec = Table.BITCOIN;
            const original_data = generateRandomBytesArray(random, 1, 256);

            const encoded_data = try endec.encodeAlloc(allocator, original_data.constSlice());
            defer allocator.free(encoded_data);

            const decoded_data = try endec.decodeAlloc(allocator, encoded_data);
            defer allocator.free(decoded_data);
        }
    };

    var prng = std.Random.DefaultPrng.init(12345);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, S.testFailing, .{prng.random()});
}

fn generateRandomBytesArray(
    random: std.Random,
    min_length: usize,
    comptime max_length: usize,
) std.BoundedArray(u8, max_length) {
    std.debug.assert(min_length <= max_length);
    var result: std.BoundedArray(u8, max_length) = .{};
    result.len = random.intRangeAtMost(
        std.math.IntFittingRange(0, max_length),
        @intCast(min_length),
        max_length,
    );
    random.bytes(result.slice());
    return result;
}
