const std = @import("std");
const crypto = std.crypto;

pub const JwtError = error{
    InvalidToken,
    ExpiredToken,
    InvalidFormat,
    InvalidSignature,
    EncodingFailed,
    DecodingFailed,
};

const b64url_encoder = std.base64.urlSafeNoPad.Encoder;
const b64url_decoder = std.base64.urlSafeNoPad.Decoder;

pub fn generateToken(allocator: std.mem.Allocator, user_id: u64, secret: []const u8, expiry_secs: u32) JwtError![]const u8 {
    const now = std.time.timestamp();
    const exp = now + @as(i64, expiry_secs);

    const header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    const payload = std.fmt.allocPrint(allocator, "{{\"sub\":{},\"exp\":{}}}", .{ user_id, exp }) catch return JwtError.EncodingFailed;

    _ = b64url_encoder.calcSize(header.len);
    _ = b64url_encoder.calcSize(payload.len);

    var header_b64_buf: [128]u8 = undefined;
    const header_b64 = b64url_encoder.encode(&header_b64_buf, header);

    var payload_b64_buf: [256]u8 = undefined;
    const payload_b64 = b64url_encoder.encode(&payload_b64_buf, payload);

    const signing_input_len = header_b64.len + 1 + payload_b64.len;
    const signing_input = allocator.alloc(u8, signing_input_len) catch return JwtError.EncodingFailed;
    @memcpy(signing_input[0..header_b64.len], header_b64);
    signing_input[header_b64.len] = '.';
    @memcpy(signing_input[header_b64.len + 1 ..], payload_b64);

    var mac: [crypto.auth.hmac.sha256.MinMacLength]u8 = undefined;
    crypto.auth.hmac.sha256.create(&mac, signing_input, secret);
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

pub fn validateToken(token: []const u8, secret: []const u8) JwtError!u64 {
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return JwtError.InvalidFormat;
    const second_dot = std.mem.indexOfScalarPos(u8, token, first_dot + 1, '.') orelse return JwtError.InvalidFormat;

    _ = token[0..first_dot];
    const payload_b64 = token[first_dot + 1 .. second_dot];
    const sig_b64 = token[second_dot + 1 ..];

    const signing_input = token[0..second_dot];

    const mac_len = b64url_decoder.calcSizeForSlice(sig_b64) catch return JwtError.InvalidFormat;
    if (mac_len != crypto.auth.hmac.sha256.MinMacLength) return JwtError.InvalidSignature;
    var expected_mac: [crypto.auth.hmac.sha256.MinMacLength]u8 = undefined;
    b64url_decoder.decode(&expected_mac, sig_b64) catch return JwtError.InvalidFormat;

    var actual_mac: [crypto.auth.hmac.sha256.MinMacLength]u8 = undefined;
    crypto.auth.hmac.sha256.create(&actual_mac, signing_input, secret);

    if (!crypto.utils.timingSafeEql([crypto.auth.hmac.sha256.MinMacLength]u8, expected_mac, actual_mac)) {
        return JwtError.InvalidSignature;
    }

    const payload_len = b64url_decoder.calcSizeForSlice(payload_b64) catch return JwtError.InvalidFormat;
    const payload_buf = std.heap.page_allocator.alloc(u8, payload_len) catch return JwtError.DecodingFailed;
    defer std.heap.page_allocator.free(payload_buf);
    b64url_decoder.decode(payload_buf, payload_b64) catch return JwtError.InvalidFormat;
    const payload_str = payload_buf;

    const sub_val = parseJsonFieldU64(payload_str, "sub") orelse return JwtError.InvalidToken;
    const exp_val = parseJsonFieldI64(payload_str, "exp") orelse return JwtError.InvalidToken;

    const now = std.time.timestamp();
    if (exp_val < now) return JwtError.ExpiredToken;

    return sub_val;
}

fn parseJsonFieldU64(json: []const u8, key: []const u8) ?u64 {
    const search = std.fmt.allocPrint(std.heap.page_allocator, "\"{s}\":", .{key}) catch return null;
    defer std.heap.page_allocator.free(search);
    const start = std.mem.indexOf(u8, json, search) orelse return null;
    const val_start = start + search.len;
    var end = val_start;
    while (end < json.len and json[end] != ',' and json[end] != '}') : (end += 1) {}
    const val_str = std.mem.trim(u8, json[val_start..end], " ");
    return std.fmt.parseInt(u64, val_str, 10) catch return null;
}

fn parseJsonFieldI64(json: []const u8, key: []const u8) ?i64 {
    const search = std.fmt.allocPrint(std.heap.page_allocator, "\"{s}\":", .{key}) catch return null;
    defer std.heap.page_allocator.free(search);
    const start = std.mem.indexOf(u8, json, search) orelse return null;
    const val_start = start + search.len;
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

    const user_id = try validateToken(token, secret);
    try std.testing.expectEqual(@as(u64, 42), user_id);
}

test "JWT expired token rejected" {
    const allocator = std.testing.allocator;
    const secret = "test-secret-key";
    const token = try generateToken(allocator, 42, secret, 0);
    defer allocator.free(token);

    const result = validateToken(token, secret);
    try std.testing.expectEqual(JwtError.ExpiredToken, result);
}

test "JWT wrong secret rejected" {
    const allocator = std.testing.allocator;
    const token = try generateToken(allocator, 42, "secret-a", 3600);
    defer allocator.free(token);

    const result = validateToken(token, "secret-b");
    try std.testing.expectEqual(JwtError.InvalidSignature, result);
}

test "JWT malformed token rejected" {
    const result = validateToken("not-a-jwt", "secret");
    try std.testing.expectEqual(JwtError.InvalidFormat, result);
}
