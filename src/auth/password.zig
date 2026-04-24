const std = @import("std");

pub const PasswordError = error{
    HashFailed,
    VerifyFailed,
};

const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn hashPassword(allocator: std.mem.Allocator, password: []const u8, salt: []const u8) PasswordError![]const u8 {
    var hasher = Sha256.init(.{});
    hasher.update(salt);
    hasher.update(password);
    var hash: [Sha256.digest_length]u8 = undefined;
    hasher.final(&hash);
    const hex_len = hash.len * 2;
    const result = allocator.alloc(u8, hex_len) catch return PasswordError.HashFailed;
    _ = std.fmt.bufPrint(result, "{}", .{std.fmt.fmtSliceHexLower(&hash)}) catch return PasswordError.HashFailed;
    return result;
}

pub fn generateSalt(allocator: std.mem.Allocator) PasswordError![]const u8 {
    var buf: [32]u8 = undefined;
    std.crypto.random.bytes(&buf);
    const hex_len = buf.len * 2;
    const salt = allocator.alloc(u8, hex_len) catch return PasswordError.HashFailed;
    _ = std.fmt.bufPrint(salt, "{}", .{std.fmt.fmtSliceHexLower(&buf)}) catch return PasswordError.HashFailed;
    return salt;
}

pub fn formatStoredHash(allocator: std.mem.Allocator, salt: []const u8, hash: []const u8) PasswordError![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}${s}", .{ salt, hash }) catch PasswordError.HashFailed;
}

pub fn parseStoredHash(stored: []const u8) ?struct { salt: []const u8, hash: []const u8 } {
    const sep = std.mem.indexOfScalar(u8, stored, '$') orelse return null;
    return .{
        .salt = stored[0..sep],
        .hash = stored[sep + 1 ..],
    };
}

pub fn verifyPassword(allocator: std.mem.Allocator, password: []const u8, stored_hash: []const u8) PasswordError!bool {
    const parsed = parseStoredHash(stored_hash) orelse return PasswordError.VerifyFailed;
    const computed = hashPassword(allocator, password, parsed.salt) catch return PasswordError.VerifyFailed;
    defer allocator.free(computed);
    if (computed.len != parsed.hash.len) return false;
    const match = std.crypto.utils.timingSafeEql([]const u8, computed, parsed.hash);
    return match;
}

test "password hash round-trip" {
    const allocator = std.testing.allocator;
    const salt = try generateSalt(allocator);
    defer allocator.free(salt);
    const hash = try hashPassword(allocator, "hunter2", salt);
    defer allocator.free(hash);
    const stored = try formatStoredHash(allocator, salt, hash);
    defer allocator.free(stored);
    const valid = try verifyPassword(allocator, "hunter2", stored);
    try std.testing.expect(valid);
}

test "password wrong password rejected" {
    const allocator = std.testing.allocator;
    const salt = try generateSalt(allocator);
    defer allocator.free(salt);
    const hash = try hashPassword(allocator, "hunter2", salt);
    defer allocator.free(hash);
    const stored = try formatStoredHash(allocator, salt, hash);
    defer allocator.free(stored);
    const valid = try verifyPassword(allocator, "wrongpass", stored);
    try std.testing.expect(!valid);
}

test "password generate salt is unique" {
    const allocator = std.testing.allocator;
    const s1 = try generateSalt(allocator);
    defer allocator.free(s1);
    const s2 = try generateSalt(allocator);
    defer allocator.free(s2);
    try std.testing.expect(!std.mem.eql(u8, s1, s2));
}
