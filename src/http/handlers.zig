// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025 Price Tracker Contributors

const std = @import("std");
const router = @import("router.zig");
const jwt_mod = @import("../auth/jwt.zig");
const password_mod = @import("../auth/password.zig");
const crud = @import("../db/crud.zig");
const data_model = @import("../db/data_model.zig");
const sqlite = @import("../db/sqlite.zig");

pub const HandlerError = error{
    Unauthorized,
    Forbidden,
    BadRequest,
    NotFound,
    InternalError,
    DuplicateUsername,
    OutOfMemory,
    InvalidFormat,
};

pub const Response = struct {
    status: u16,
    body: []const u8,

    pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
        if (self.body.len > 0) allocator.free(self.body);
    }
};

pub const Request = struct {
    method: router.Method,
    path: []const u8,
    body: []const u8,
    auth_header: ?[]const u8,
    user_id: ?u64,
    params: *std.StringHashMap([]const u8),
};

pub const ServerConfig = struct {
    db: sqlite.Sqlite,
    allocator: std.mem.Allocator,
    jwt_secret: []const u8,
    jwt_expiry: u32,
    io: std.Io,
};

fn unixTimestamp() i64 {
    var ts: std.posix.timespec = undefined;
    const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @intCast(ts.sec);
}

pub fn authenticateRequest(allocator: std.mem.Allocator, auth_header: ?[]const u8, secret: []const u8) ?u64 {
    const header = auth_header orelse return null;
    if (!std.mem.startsWith(u8, header, "Bearer ")) return null;
    const token = header["Bearer ".len..];
    return jwt_mod.validateToken(allocator, token, secret) catch null;
}

pub fn dispatch(cfg: ServerConfig, req: Request, handler_id: router.HandlerId) HandlerError!Response {
    return switch (handler_id) {
        .register => handleRegister(cfg, req),
        .login => handleLogin(cfg, req),
        .me => handleMe(cfg, req),
        .listProducts => handleListProducts(cfg, req),
        .getProduct => handleGetProduct(cfg, req),
        .createProduct => handleCreateProduct(cfg, req),
        .updateProduct => handleUpdateProduct(cfg, req),
        .deleteProduct => handleDeleteProduct(cfg, req),
        .listListings => handleListListings(cfg, req),
        .getListing => handleGetListing(cfg, req),
        .createListing => handleCreateListing(cfg, req),
        .updateListing => handleUpdateListing(cfg, req),
        .deleteListing => handleDeleteListing(cfg, req),
        .listPricesByListing => handleListPricesByListing(cfg, req),
        .listPricesByProduct => handleListPricesByProduct(cfg, req),
        .healthz => handleHealthz(cfg, req),
        .readyz => handleReadyz(cfg, req),
    };
}

pub fn handleRegister(cfg: ServerConfig, req: Request) HandlerError!Response {
    const username = parseJsonString(cfg.allocator, req.body, "username") catch return HandlerError.BadRequest;
    defer cfg.allocator.free(username);
    const pw = parseJsonString(cfg.allocator, req.body, "password") catch return HandlerError.BadRequest;
    defer cfg.allocator.free(pw);

    if (username.len == 0 or pw.len == 0) return HandlerError.BadRequest;

    const existing = crud.getUserByUsername(cfg.db, cfg.allocator, username) catch return HandlerError.InternalError;
    if (existing) |user| {
        cfg.allocator.free(user.username);
        cfg.allocator.free(user.password_hash);
        return HandlerError.DuplicateUsername;
    }

    const hash = password_mod.hashPassword(cfg.allocator, cfg.io, pw) catch return HandlerError.InternalError;

    const user = data_model.User{
        .id = 0,
        .username = username,
        .password_hash = hash,
        .created_at = unixTimestamp(),
        .is_admin = false,
    };
    const id = crud.insertUser(cfg.db, user) catch return HandlerError.InternalError;

    const token = jwt_mod.generateToken(cfg.allocator, id, cfg.jwt_secret, cfg.jwt_expiry) catch return HandlerError.InternalError;
    defer cfg.allocator.free(token);

    const body = try allocPrintTokenResponse(cfg.allocator, id, token);
    return .{ .status = 201, .body = body };
}

pub fn handleLogin(cfg: ServerConfig, req: Request) HandlerError!Response {
    const username = parseJsonString(cfg.allocator, req.body, "username") catch return HandlerError.BadRequest;
    defer cfg.allocator.free(username);
    const pw = parseJsonString(cfg.allocator, req.body, "password") catch return HandlerError.BadRequest;
    defer cfg.allocator.free(pw);

    const user_opt = crud.getUserByUsername(cfg.db, cfg.allocator, username) catch return HandlerError.InternalError;
    const user = user_opt orelse return HandlerError.Unauthorized;

    const valid = password_mod.verifyPassword(cfg.allocator, pw, user.password_hash) catch false;
    if (!valid) {
        cfg.allocator.free(user.username);
        cfg.allocator.free(user.password_hash);
        return HandlerError.Unauthorized;
    }
    if (password_mod.needsRehash(user.password_hash)) {
        const new_hash = password_mod.hashPassword(cfg.allocator, cfg.io, pw) catch null;
        if (new_hash) |h| {
            _ = crud.updateUserPassword(cfg.db, user.id, h) catch {};
            cfg.allocator.free(h);
        }
    }

    const token = jwt_mod.generateToken(cfg.allocator, user.id, cfg.jwt_secret, cfg.jwt_expiry) catch return HandlerError.InternalError;
    defer cfg.allocator.free(token);

    const body = try allocPrintTokenResponse(cfg.allocator, user.id, token);
    cfg.allocator.free(user.username);
    cfg.allocator.free(user.password_hash);
    return .{ .status = 200, .body = body };
}

pub fn handleMe(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const user_opt = crud.getUserById(cfg.db, cfg.allocator, uid) catch return HandlerError.InternalError;
    const user = user_opt orelse return HandlerError.NotFound;

    const body = try allocPrintUserResponse(cfg.allocator, user.id, user.username, user.is_admin);
    cfg.allocator.free(user.username);
    cfg.allocator.free(user.password_hash);
    return .{ .status = 200, .body = body };
}

pub fn handleListProducts(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const products = crud.listProductsByUserId(cfg.db, cfg.allocator, uid) catch return HandlerError.InternalError;
    defer {
        for (products) |p| freeProduct(cfg.allocator, p);
        cfg.allocator.free(products);
    }
    const body = allocPrintProductList(cfg.allocator, products) catch return HandlerError.OutOfMemory;
    return .{ .status = 200, .body = body };
}

pub fn handleGetProduct(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    const body = allocPrintProduct(cfg.allocator, product) catch return HandlerError.OutOfMemory;
    return .{ .status = 200, .body = body };
}

pub fn handleCreateProduct(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const product = parseProductFromBody(cfg.allocator, req.body, uid) catch return HandlerError.BadRequest;
    const id = crud.insertProduct(cfg.db, product) catch return HandlerError.InternalError;
    const body = try allocPrintIdResponse(cfg.allocator, id);
    return .{ .status = 201, .body = body };
}

pub fn handleUpdateProduct(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const existing_opt = crud.getProductById(cfg.db, cfg.allocator, id) catch return HandlerError.InternalError;
    const existing = existing_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, existing);
    if (existing.user_id != uid) return HandlerError.Forbidden;
    var product = parseProductFromBody(cfg.allocator, req.body, uid) catch return HandlerError.BadRequest;
    product.id = id;
    crud.updateProduct(cfg.db, product) catch return HandlerError.InternalError;
    const body = try allocPrintIdResponse(cfg.allocator, id);
    return .{ .status = 200, .body = body };
}

pub fn handleDeleteProduct(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const existing_opt = crud.getProductById(cfg.db, cfg.allocator, id) catch return HandlerError.InternalError;
    const existing = existing_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, existing);
    if (existing.user_id != uid) return HandlerError.Forbidden;
    crud.deleteProduct(cfg.db, id) catch return HandlerError.InternalError;
    return .{ .status = 200, .body = "{\"deleted\":true}" };
}

pub fn handleListListings(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const product_id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, product_id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    const listings = crud.listListingsByProductId(cfg.db, cfg.allocator, product_id) catch return HandlerError.InternalError;
    defer {
        for (listings) |l| freeListing(cfg.allocator, l);
        cfg.allocator.free(listings);
    }
    const body = allocPrintListingList(cfg.allocator, listings) catch return HandlerError.OutOfMemory;
    return .{ .status = 200, .body = body };
}

pub fn handleGetListing(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const listing_opt = crud.getListingById(cfg.db, cfg.allocator, id) catch return HandlerError.InternalError;
    const listing = listing_opt orelse return HandlerError.NotFound;
    defer freeListing(cfg.allocator, listing);
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, listing.product_id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    const body = allocPrintListing(cfg.allocator, listing) catch return HandlerError.OutOfMemory;
    return .{ .status = 200, .body = body };
}

pub fn handleCreateListing(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const product_id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, product_id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    const listing = parseListingFromBody(cfg.allocator, req.body, product_id) catch return HandlerError.BadRequest;
    const new_id = crud.insertListing(cfg.db, listing) catch return HandlerError.InternalError;
    const body = try allocPrintIdResponse(cfg.allocator, new_id);
    return .{ .status = 201, .body = body };
}

pub fn handleUpdateListing(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const existing_opt = crud.getListingById(cfg.db, cfg.allocator, id) catch return HandlerError.InternalError;
    const existing = existing_opt orelse return HandlerError.NotFound;
    defer freeListing(cfg.allocator, existing);
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, existing.product_id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    var listing = parseListingFromBody(cfg.allocator, req.body, existing.product_id) catch return HandlerError.BadRequest;
    listing.id = id;
    crud.updateListing(cfg.db, listing) catch return HandlerError.InternalError;
    const body = try allocPrintIdResponse(cfg.allocator, id);
    return .{ .status = 200, .body = body };
}

pub fn handleDeleteListing(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const existing_opt = crud.getListingById(cfg.db, cfg.allocator, id) catch return HandlerError.InternalError;
    const existing = existing_opt orelse return HandlerError.NotFound;
    defer freeListing(cfg.allocator, existing);
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, existing.product_id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    crud.deleteListing(cfg.db, id) catch return HandlerError.InternalError;
    return .{ .status = 200, .body = "{\"deleted\":true}" };
}

pub fn handleListPricesByListing(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const listing_id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const listing_opt = crud.getListingById(cfg.db, cfg.allocator, listing_id) catch return HandlerError.InternalError;
    const listing = listing_opt orelse return HandlerError.NotFound;
    defer freeListing(cfg.allocator, listing);
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, listing.product_id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    const prices = crud.listPricesByListingId(cfg.db, cfg.allocator, listing_id, 100, 0) catch return HandlerError.InternalError;
    defer {
        for (prices) |p| freePrice(cfg.allocator, p);
        cfg.allocator.free(prices);
    }
    const body = allocPrintPriceList(cfg.allocator, prices) catch return HandlerError.OutOfMemory;
    return .{ .status = 200, .body = body };
}

pub fn handleListPricesByProduct(cfg: ServerConfig, req: Request) HandlerError!Response {
    const uid = req.user_id orelse return HandlerError.Unauthorized;
    const id_str = req.params.get("id") orelse return HandlerError.BadRequest;
    const product_id = std.fmt.parseInt(u64, id_str, 10) catch return HandlerError.BadRequest;
    const product_opt = crud.getProductById(cfg.db, cfg.allocator, product_id) catch return HandlerError.InternalError;
    const product = product_opt orelse return HandlerError.NotFound;
    defer freeProduct(cfg.allocator, product);
    if (product.user_id != uid) return HandlerError.Forbidden;
    const prices = crud.listPricesByProductId(cfg.db, cfg.allocator, product_id) catch return HandlerError.InternalError;
    defer {
        for (prices) |p| freePrice(cfg.allocator, p);
        cfg.allocator.free(prices);
    }
    const body = allocPrintPriceList(cfg.allocator, prices) catch return HandlerError.OutOfMemory;
    return .{ .status = 200, .body = body };
}

pub fn handleHealthz(_: ServerConfig, _: Request) HandlerError!Response {
    return .{ .status = 200, .body = "{\"status\":\"ok\"}" };
}

pub fn handleReadyz(_: ServerConfig, _: Request) HandlerError!Response {
    return .{ .status = 200, .body = "{\"status\":\"ready\"}" };
}

fn writeJsonEscaped(writer: anytype, input: []const u8) @TypeOf(writer).Error!void {
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        switch (input[i]) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (input[i] < 0x20) {
                    try writer.print("\\u00{x:0>2}", .{input[i]});
                } else {
                    try writer.writeByte(input[i]);
                }
            },
        }
    }
}

fn parseJsonString(allocator: std.mem.Allocator, body: []const u8, key: []const u8) ![]const u8 {
    const key_prefix = "\"" ++ key ++ "\":";
    const start = std.mem.indexOf(u8, body, key_prefix) orelse return error.InvalidFormat;
    var i: usize = start + key_prefix.len;
    while (i < body.len and body[i] == ' ') : (i += 1) {}
    if (i >= body.len or body[i] != '"') return error.InvalidFormat;
    i += 1;
    const val_start = i;
    while (i < body.len) : (i += 1) {
        if (body[i] == '\\') {
            i += 1;
        } else if (body[i] == '"') {
            break;
        }
    }
    if (i >= body.len) return error.InvalidFormat;
    return try allocator.dupe(u8, body[val_start..i]);
}

fn parseJsonF64(allocator: std.mem.Allocator, body: []const u8, key: []const u8) ?f64 {
    const key_prefix = "\"" ++ key ++ "\":";
    const start = std.mem.indexOf(u8, body, key_prefix) orelse return null;
    const val_start = start + key_prefix.len;
    var end = val_start;
    while (end < body.len and body[end] != ',' and body[end] != '}') : (end += 1) {}
    const val_str = std.mem.trim(u8, body[val_start..end], " \"");
    _ = allocator;
    return std.fmt.parseFloat(f64, val_str) catch null;
}

fn parseJsonU32(allocator: std.mem.Allocator, body: []const u8, key: []const u8) ?u32 {
    const key_prefix = "\"" ++ key ++ "\":";
    const start = std.mem.indexOf(u8, body, key_prefix) orelse return null;
    const val_start = start + key_prefix.len;
    var end = val_start;
    while (end < body.len and body[end] != ',' and body[end] != '}') : (end += 1) {}
    const val_str = std.mem.trim(u8, body[val_start..end], " \"");
    _ = allocator;
    return std.fmt.parseInt(u32, val_str, 10) catch null;
}

fn parseProductFromBody(allocator: std.mem.Allocator, body: []const u8, user_id: u64) !data_model.Product {
    const name = try parseJsonString(allocator, body, "name");
    const search_term = parseJsonString(allocator, body, "search_term") catch null;
    const category = parseJsonString(allocator, body, "category") catch null;
    const unit_type = parseJsonString(allocator, body, "unit_type") catch null;
    const target_price = parseJsonF64(allocator, body, "target_price") orelse 0.0;
    const unit_quantity = parseJsonF64(allocator, body, "unit_quantity") orelse 1.0;
    const check_interval = parseJsonU32(allocator, body, "check_interval") orelse 3600;
    const now = unixTimestamp();
    return data_model.Product{
        .id = 0,
        .user_id = user_id,
        .name = name,
        .search_term = search_term,
        .category = category,
        .unit_type = unit_type,
        .unit_quantity = unit_quantity,
        .target_price = target_price,
        .value_estimate = null,
        .check_interval = check_interval,
        .last_checked_at = null,
        .created_at = now,
        .updated_at = now,
    };
}

fn parseListingFromBody(allocator: std.mem.Allocator, body: []const u8, product_id: u64) !data_model.Listing {
    const url = try parseJsonString(allocator, body, "url");
    const store_name = parseJsonString(allocator, body, "store_name") catch null;
    const selector_config = parseJsonString(allocator, body, "selector_config") catch null;
    const listing_type_alloc = parseJsonString(allocator, body, "listing_type") catch null;
    if (listing_type_alloc) |s| allocator.free(s);
    const listing_type = if (listing_type_alloc) |s|
        std.meta.stringToEnum(data_model.ListingType, s) orelse .fixed
    else
        .fixed;
    return data_model.Listing{
        .id = 0,
        .product_id = product_id,
        .url = url,
        .store_name = store_name,
        .listing_type = listing_type,
        .selector_config = selector_config,
        .is_active = true,
        .created_at = unixTimestamp(),
    };
}

fn freeProduct(allocator: std.mem.Allocator, p: data_model.Product) void {
    allocator.free(p.name);
    if (p.search_term) |s| allocator.free(s);
    if (p.category) |s| allocator.free(s);
    if (p.unit_type) |s| allocator.free(s);
}

fn freeListing(allocator: std.mem.Allocator, l: data_model.Listing) void {
    allocator.free(l.url);
    if (l.store_name) |s| allocator.free(s);
    if (l.selector_config) |s| allocator.free(s);
}

fn freePrice(allocator: std.mem.Allocator, p: data_model.Price) void {
    allocator.free(p.currency);
    if (p.raw_extract) |s| allocator.free(s);
}

fn allocPrintProduct(allocator: std.mem.Allocator, p: data_model.Product) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = buf.writer();
    try w.writeAll("{\"id\":");
    try std.fmt.formatInt(p.id, 10, .lower, .{}, w);
    try w.writeAll(",\"user_id\":");
    try std.fmt.formatInt(p.user_id, 10, .lower, .{}, w);
    try w.writeAll(",\"name\":\"");
    try writeJsonEscaped(w, p.name);
    try w.writeAll("\",\"target_price\":");
    try std.fmt.formatFloat(&w, p.target_price, .{ .mode = .decimal, .precision = 2 });
    try w.writeAll(",\"unit_quantity\":");
    try std.fmt.formatFloat(&w, p.unit_quantity, .{ .mode = .decimal, .precision = 2 });
    try w.writeAll(",\"check_interval\":");
    try std.fmt.formatInt(p.check_interval, 10, .lower, .{}, w);
    try w.writeAll(",\"created_at\":");
    try std.fmt.formatInt(p.created_at, 10, .lower, .{}, w);
    try w.writeByte('}');
    return buf.toOwnedSlice();
}

fn allocPrintProductList(allocator: std.mem.Allocator, products: []data_model.Product) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try buf.append('[');
    for (products, 0..) |p, i| {
        if (i > 0) try buf.append(',');
        const item = try allocPrintProduct(allocator, p);
        defer allocator.free(item);
        try buf.appendSlice(item);
    }
    try buf.append(']');
    return buf.toOwnedSlice();
}

fn allocPrintListing(allocator: std.mem.Allocator, l: data_model.Listing) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = buf.writer();
    try w.writeAll("{\"id\":");
    try std.fmt.formatInt(l.id, 10, .lower, .{}, w);
    try w.writeAll(",\"product_id\":");
    try std.fmt.formatInt(l.product_id, 10, .lower, .{}, w);
    try w.writeAll(",\"url\":\"");
    try writeJsonEscaped(w, l.url);
    try w.writeAll("\",\"listing_type\":\"");
    try writeJsonEscaped(w, @tagName(l.listing_type));
    try w.writeAll("\",\"is_active\":");
    try w.writeAll(if (l.is_active) "true" else "false");
    try w.writeAll(",\"created_at\":");
    try std.fmt.formatInt(l.created_at, 10, .lower, .{}, w);
    try w.writeByte('}');
    return buf.toOwnedSlice();
}

fn allocPrintListingList(allocator: std.mem.Allocator, listings: []data_model.Listing) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try buf.append('[');
    for (listings, 0..) |l, i| {
        if (i > 0) try buf.append(',');
        const item = try allocPrintListing(allocator, l);
        defer allocator.free(item);
        try buf.appendSlice(item);
    }
    try buf.append(']');
    return buf.toOwnedSlice();
}

fn allocPrintPrice(allocator: std.mem.Allocator, p: data_model.Price) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = buf.writer();
    try w.writeAll("{\"id\":");
    try std.fmt.formatInt(p.id, 10, .lower, .{}, w);
    try w.writeAll(",\"listing_id\":");
    try std.fmt.formatInt(p.listing_id, 10, .lower, .{}, w);
    try w.writeAll(",\"price\":");
    try std.fmt.formatFloat(&w, p.price, .{ .mode = .decimal, .precision = 2 });
    try w.writeAll(",\"currency\":\"");
    try writeJsonEscaped(w, p.currency);
    try w.writeAll("\",\"stock_status\":\"");
    try writeJsonEscaped(w, @tagName(p.stock_status));
    try w.writeAll("\",\"checked_at\":");
    try std.fmt.formatInt(p.checked_at, 10, .lower, .{}, w);
    try w.writeByte('}');
    return buf.toOwnedSlice();
}

fn allocPrintPriceList(allocator: std.mem.Allocator, prices: []data_model.Price) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try buf.append('[');
    for (prices, 0..) |p, i| {
        if (i > 0) try buf.append(',');
        const item = try allocPrintPrice(allocator, p);
        defer allocator.free(item);
        try buf.appendSlice(item);
    }
    try buf.append(']');
    return buf.toOwnedSlice();
}

fn allocPrintTokenResponse(allocator: std.mem.Allocator, user_id: u64, token: []const u8) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = buf.writer();
    try w.writeAll("{\"user_id\":");
    try std.fmt.formatInt(user_id, 10, .lower, .{}, w);
    try w.writeAll(",\"token\":\"");
    try writeJsonEscaped(w, token);
    try w.writeAll("\"}");
    return buf.toOwnedSlice();
}

fn allocPrintUserResponse(allocator: std.mem.Allocator, id: u64, username: []const u8, is_admin: bool) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = buf.writer();
    try w.writeAll("{\"id\":");
    try std.fmt.formatInt(id, 10, .lower, .{}, w);
    try w.writeAll(",\"username\":\"");
    try writeJsonEscaped(w, username);
    try w.writeAll("\",\"is_admin\":");
    try w.writeAll(if (is_admin) "true" else "false");
    try w.writeByte('}');
    return buf.toOwnedSlice();
}

fn allocPrintIdResponse(allocator: std.mem.Allocator, id: u64) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    const w = buf.writer();
    try w.writeAll("{\"id\":");
    try std.fmt.formatInt(id, 10, .lower, .{}, w);
    try w.writeByte('}');
    return buf.toOwnedSlice();
}

test "authenticateRequest valid token" {
    const allocator = std.testing.allocator;
    const secret = "test-secret";
    const token = try jwt_mod.generateToken(allocator, 42, secret, 3600);
    defer allocator.free(token);
    const header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
    defer allocator.free(header);
    const uid = authenticateRequest(std.testing.allocator, header, secret);
    try std.testing.expectEqual(@as(u64, 42), uid.?);
}

test "authenticateRequest missing header" {
    const uid = authenticateRequest(std.testing.allocator, null, "secret");
    try std.testing.expect(uid == null);
}

test "authenticateRequest invalid token" {
    const uid = authenticateRequest(std.testing.allocator, "Bearer invalid", "secret");
    try std.testing.expect(uid == null);
}

test "authenticateRequest wrong scheme" {
    const uid = authenticateRequest(std.testing.allocator, "Basic abc123", "secret");
    try std.testing.expect(uid == null);
}

test "parseJsonString basic" {
    const allocator = std.testing.allocator;
    const result = try parseJsonString(allocator, "{\"name\":\"hello\"}", "name");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello", result);
}

test "parseJsonString missing key" {
    const allocator = std.testing.allocator;
    const result = parseJsonString(allocator, "{\"name\":\"hello\"}", "missing");
    try std.testing.expectEqual(HandlerError.InvalidFormat, result);
}

test "writeJsonEscaped escapes special characters" {
    const allocator = std.testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = buf.writer();
    try writeJsonEscaped(w, "hello\"world\\test\nnew\rline\ttab\x01end");
    try std.testing.expectEqualStrings("hello\\\"world\\\\test\\nnew\\rline\\ttab\\u0001end", buf.items);
}

test "parseJsonString escaped quote" {
    const allocator = std.testing.allocator;
    const result = try parseJsonString(allocator, "{\"name\":\"hello\\\"world\"}", "name");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello\\\"world", result);
}

test "handleHealthz returns ok" {
    const cfg = ServerConfig{
        .db = undefined,
        .allocator = std.testing.allocator,
        .jwt_secret = "secret",
        .jwt_expiry = 3600,
        .io = std.testing.io,
    };
    var params = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer params.deinit();
    const req = Request{
        .method = .GET,
        .path = "/healthz",
        .body = "",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const resp = try handleHealthz(cfg, req);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
}

test "handleReadyz returns ready" {
    const cfg = ServerConfig{
        .db = undefined,
        .allocator = std.testing.allocator,
        .jwt_secret = "secret",
        .jwt_expiry = 3600,
        .io = std.testing.io,
    };
    var params = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer params.deinit();
    const req = Request{
        .method = .GET,
        .path = "/readyz",
        .body = "",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const resp = try handleReadyz(cfg, req);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("{\"status\":\"ready\"}", resp.body);
}
