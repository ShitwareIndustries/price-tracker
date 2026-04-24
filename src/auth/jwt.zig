// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025 Price Tracker Contributors

const std = @import("std");

pub const JwtError = error{
    InvalidToken,
    ExpiredToken,
    InvalidFormat,
    InvalidSignature,
    EncodingFailed,
    DecodingFailed,
};

const b64url_encoder = std.base64.url_safe_no_pad.Encoder;
const b64url_decoder = std.base64.url_safe_no_pad.Decoder;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

fn unixTimestamp() i64 {
    var ts: std.posix.timespec = undefined;
    const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @intCast(ts.sec);
}

pub fn generateToken(allocator: std.mem.Allocator, user_id: u64, secret: []const u8, expiry_secs: u32) JwtError![]const u8 {
    const now = unixTimestamp();
    const exp = now + @as(i64, expiry_secs);

    const header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    var payload_buf: [256]u8 = undefined;
    const payload = std.fmt.bufPrint(&payload_buf, "{{\"sub\":{},\"exp\":{}}}", .{ user_id, exp }) catch return JwtError.EncodingFailed;

    var header_b64_buf: [128]u8 = undefined;
    const header_b64 = b64url_encoder.encode(&header_b64_buf, header);

    var payload_b64_buf: [256]u8 = undefined;
    const payload_b64 = b64url_encoder.encode(&payload_b64_buf, payload);

    const signing_input_len = header_b64.len + 1 + payload_b64.len;
    const signing_input = allocator.alloc(u8, signing_input_len) catch return JwtError.EncodingFailed;
    @memcpy(signing_input[0..header_b64.len], header_b64);
    signing_input[header_b64.len] = '.';
    @memcpy(signing_input[header_b64.len + 1 ..], payload_b64);

    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, signing_input, secret);
    allocator.free(signing_input);

    _ = b64url_encoder.calcSize(mac.len);
    var sig_b64_buf: [64]u8 = undefined;
    const sig_b64 = b64url_encoder.encode(&sig_b64_buf, &mac);

    const total_len = header_b64.len + 1 + payload_b64.len + 1 + sig_b64.len;
    const token = allocator.alloc(u8, total_len) catch return JwtError.EncodingFailed;
    @memcpy(token[0..header_b64.len], header_b64);
    token[header_b64.len] = '.';
    @memcpy(token[header_b64.len + 1 ..][0..payload_b64.len], payload_b64);
    token[header_b64.len + 1 + payload_b64.len] = '.';
    @memcpy(token[header_b64.len + 1 + payload_b64.len + 1 ..], sig_b64);

    return token;
}

pub fn validateToken(allocator: std.mem.Allocator, token: []const u8, secret: []const u8) JwtError!u64 {
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return JwtError.InvalidFormat;
    const second_dot = std.mem.indexOfScalarPos(u8, token, first_dot + 1, '.') orelse return JwtError.InvalidFormat;

    _ = token[0..first_dot];
    const payload_b64 = token[first_dot + 1 .. second_dot];
    const sig_b64 = token[second_dot + 1 ..];

    const signing_input = token[0..second_dot];

    const mac_len = b64url_decoder.calcSizeForSlice(sig_b64) catch return JwtError.InvalidFormat;
    if (mac_len != HmacSha256.mac_length) return JwtError.InvalidSignature;
    var expected_mac: [HmacSha256.mac_length]u8 = undefined;
    b64url_decoder.decode(&expected_mac, sig_b64) catch return JwtError.InvalidFormat;

    var actual_mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&actual_mac, signing_input, secret);

    if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected_mac, actual_mac)) {
        return JwtError.InvalidSignature;
    }

    const payload_len = b64url_decoder.calcSizeForSlice(payload_b64) catch return JwtError.InvalidFormat;
    const payload_buf = allocator.alloc(u8, payload_len) catch return JwtError.DecodingFailed;
    defer allocator.free(payload_buf);
    b64url_decoder.decode(payload_buf, payload_b64) catch return JwtError.InvalidFormat;
    const payload_str = payload_buf;

    const sub_val = parseJsonFieldU64(payload_str, "sub") orelse return JwtError.InvalidToken;
    const exp_val = parseJsonFieldI64(payload_str, "exp") orelse return JwtError.InvalidToken;

    const now = unixTimestamp();
    if (exp_val < now) return JwtError.ExpiredToken;

    return sub_val;
}

fn parseJsonFieldU64(json: []const u8, key: []const u8) ?u64 {
    const key_prefix = std.fmt.allocPrint(std.heap.page_allocator, "\"{s}\":", .{key}) catch return null;
    defer std.heap.page_allocator.free(key_prefix);
    const start = std.mem.indexOf(u8, json, key_prefix) orelse return null;
    const val_start = start + key_prefix.len;
    var end = val_start;
    while (end < json.len and json[end] != ',' and json[end] != '}') : (end += 1) {}
    const val_str = std.mem.trim(u8, json[val_start..end], " ");
    return std.fmt.parseInt(u64, val_str, 10) catch return null;
}

fn parseJsonFieldI64(json: []const u8, key: []const u8) ?i64 {
    const key_prefix = std.fmt.allocPrint(std.heap.page_allocator, "\"{s}\":", .{key}) catch return null;
    defer std.heap.page_allocator.free(key_prefix);
    const start = std.mem.indexOf(u8, json, key_prefix) orelse return null;
    const val_start = start + key_prefix.len;
    var end = val_start;
    while (end < json.len and json[end] != ',' and json[end] != '}') : (end += 1) {}
    const val_str = std.mem.trim(u8, json[val_start..end], " ");
    return std.fmt.parseInt(i64, val_str, 10) catch return null;
}

test "JWT generate + validate round-trip" {
    const allocator = std.testing.allocator;
    const secret = "test-secret-key";
    const token = try generateToken(allocator, 42, secret, 3600);
    defer allocator.free(token);

    const user_id = try validateToken(allocator, token, secret);
    try std.testing.expectEqual(@as(u64, 42), user_id);
}

test "JWT expired token rejected" {
    const allocator = std.testing.allocator;
    const secret = "test-secret-key";
    const token = try generateToken(allocator, 42, secret, 1);
    defer allocator.free(token);

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    const now: i64 = @intCast(ts.sec);

    var payload_buf: [256]u8 = undefined;
    const payload = std.fmt.bufPrint(&payload_buf, "{{\"sub\":42,\"exp\":{}}}", .{now - 1}) catch unreachable;
    const b64url_enc = std.base64.url_safe_no_pad.Encoder;

    const jwt_header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    var h_b64: [128]u8 = undefined;
    const h_enc = b64url_enc.encode(&h_b64, jwt_header);
    var p_b64: [256]u8 = undefined;
    const p_enc = b64url_enc.encode(&p_b64, payload);

    const sign_input_len = h_enc.len + 1 + p_enc.len;
    const signing_input = allocator.alloc(u8, sign_input_len) catch return;
    @memcpy(signing_input[0..h_enc.len], h_enc);
    signing_input[h_enc.len] = '.';
    @memcpy(signing_input[h_enc.len + 1 ..], p_enc);

    const HmacSha256Type = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256Type.mac_length]u8 = undefined;
    HmacSha256Type.create(&mac, signing_input, secret);
    allocator.free(signing_input);

    var s_b64: [64]u8 = undefined;
    const s_enc = b64url_enc.encode(&s_b64, &mac);

    const total_len = h_enc.len + 1 + p_enc.len + 1 + s_enc.len;
    const token_buf = allocator.alloc(u8, total_len) catch return;
    @memcpy(token_buf[0..h_enc.len], h_enc);
    token_buf[h_enc.len] = '.';
    @memcpy(token_buf[h_enc.len + 1 ..][0..p_enc.len], p_enc);
    token_buf[h_enc.len + 1 + p_enc.len] = '.';
    @memcpy(token_buf[h_enc.len + 1 + p_enc.len + 1 ..], s_enc);

    const result = validateToken(allocator, token_buf, secret);
    allocator.free(token_buf);
    try std.testing.expectEqual(JwtError.ExpiredToken, result);
}

test "JWT wrong secret rejected" {
    const allocator = std.testing.allocator;
    const token = try generateToken(allocator, 42, "secret-a", 3600);
    defer allocator.free(token);

    const result = validateToken(allocator, token, "secret-b");
    try std.testing.expectEqual(JwtError.InvalidSignature, result);
}

test "JWT malformed token rejected" {
    const result = validateToken(std.testing.allocator, "not-a-jwt", "secret");
    try std.testing.expectEqual(JwtError.InvalidFormat, result);
}
