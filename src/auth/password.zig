// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025 Price Tracker Contributors

const std = @import("std");

pub const PasswordError = error{
    HashFailed,
    VerifyFailed,
    OutOfMemory,
};

const bcrypt = std.crypto.pwhash.bcrypt;

pub fn hashPassword(allocator: std.mem.Allocator, io: std.Io, password: []const u8) PasswordError![]const u8 {
    var buf: [bcrypt.hash_length]u8 = undefined;
    const hash_str = bcrypt.strHash(
        password,
        .{
            .params = bcrypt.Params.owasp,
            .encoding = .crypt,
        },
        &buf,
        io,
    ) catch return PasswordError.HashFailed;
    return allocator.dupe(u8, hash_str) catch PasswordError.OutOfMemory;
}

pub fn verifyPassword(allocator: std.mem.Allocator, password: []const u8, stored_hash: []const u8) PasswordError!bool {
    if (isLegacyHash(stored_hash)) {
        return verifyLegacyPassword(allocator, password, stored_hash);
    }
    const result = bcrypt.strVerify(
        stored_hash,
        password,
        .{ .silently_truncate_password = false },
    ) catch return false;
    _ = result;
    return true;
}

pub fn isLegacyHash(stored_hash: []const u8) bool {
    if (std.mem.indexOfScalar(u8, stored_hash, '$')) |sep_pos| {
        const prefix = stored_hash[0..sep_pos];
        if (prefix.len == 64) {
            for (prefix) |c| {
                if (!std.ascii.isHex(c)) return false;
            }
            return true;
        }
    }
    return false;
}

pub fn needsRehash(stored_hash: []const u8) bool {
    return isLegacyHash(stored_hash);
}

fn verifyLegacyPassword(allocator: std.mem.Allocator, password: []const u8, stored_hash: []const u8) PasswordError!bool {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const parsed = parseLegacyStoredHash(stored_hash) orelse return PasswordError.VerifyFailed;
    var hasher = Sha256.init(.{});
    hasher.update(parsed.salt);
    hasher.update(password);
    var hash: [Sha256.digest_length]u8 = undefined;
    hasher.final(&hash);
    const encoded = std.fmt.bytesToHex(&hash, .lower);
    if (encoded.len != parsed.hash.len) return false;
    const computed_arr: [Sha256.digest_length * 2]u8 = encoded[0 .. Sha256.digest_length * 2].*;
    const stored_arr: [Sha256.digest_length * 2]u8 = parsed.hash[0 .. Sha256.digest_length * 2].*;
    _ = allocator;
    return std.crypto.timing_safe.eql([Sha256.digest_length * 2]u8, computed_arr, stored_arr);
}

fn parseLegacyStoredHash(stored: []const u8) ?struct { salt: []const u8, hash: []const u8 } {
    const sep = std.mem.indexOfScalar(u8, stored, '$') orelse return null;
    return .{
        .salt = stored[0..sep],
        .hash = stored[sep + 1 ..],
    };
}

test "password hash round-trip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const hash = try hashPassword(allocator, io, "hunter2");
    defer allocator.free(hash);
    try std.testing.expect(!isLegacyHash(hash));
    const valid = try verifyPassword(allocator, "hunter2", hash);
    try std.testing.expect(valid);
}

test "password wrong password rejected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const hash = try hashPassword(allocator, io, "hunter2");
    defer allocator.free(hash);
    const valid = try verifyPassword(allocator, "wrongpass", hash);
    try std.testing.expect(!valid);
}

test "password unique hashes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const h1 = try hashPassword(allocator, io, "hunter2");
    defer allocator.free(h1);
    const h2 = try hashPassword(allocator, io, "hunter2");
    defer allocator.free(h2);
    try std.testing.expect(!std.mem.eql(u8, h1, h2));
}

test "password bcrypt format" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const hash = try hashPassword(allocator, io, "testpass");
    defer allocator.free(hash);
    try std.testing.expect(std.mem.startsWith(u8, hash, "$2b$10$"));
    try std.testing.expectEqual(@as(usize, 60), hash.len);
}

test "password legacy hash detection" {
    try std.testing.expect(isLegacyHash("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2$abcdef1234567890"));
    try std.testing.expect(!isLegacyHash("$2b$10$WUQKyBCaKpziCwUXHiMVvu40dYVjkTxtWJlftl0PpjY2BxWSvFIEe"));
    try std.testing.expect(!isLegacyHash("short$hash"));
}

test "password verify legacy sha256 hash" {
    const allocator = std.testing.allocator;
    const salt = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var hasher = Sha256.init(.{});
    hasher.update(salt);
    hasher.update("hunter2");
    var hash: [Sha256.digest_length]u8 = undefined;
    hasher.final(&hash);
    const encoded = std.fmt.bytesToHex(&hash, .lower);
    const stored = try std.fmt.allocPrint(allocator, "{s}${s}", .{ salt, encoded });
    defer allocator.free(stored);
    const valid = try verifyPassword(allocator, "hunter2", stored);
    try std.testing.expect(valid);
    const invalid = try verifyPassword(allocator, "wrongpass", stored);
    try std.testing.expect(!invalid);
}

test "password needs rehash for legacy" {
    const legacy = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2$abcdef1234567890";
    try std.testing.expect(needsRehash(legacy));
    const bcrypt_hash = "$2b$10$WUQKyBCaKpziCwUXHiMVvu40dYVjkTxtWJlftl0PpjY2BxWSvFIEe";
    try std.testing.expect(!needsRehash(bcrypt_hash));
}
