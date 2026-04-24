// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025 Price Tracker Contributors

const std = @import("std");
const handlers = @import("handlers.zig");
const router_mod = @import("router.zig");
const jwt_mod = @import("../auth/jwt.zig");
const password_mod = @import("../auth/password.zig");
const sqlite = @import("../db/sqlite.zig");
const migrations = @import("../db/migrations.zig");
const crud = @import("../db/crud.zig");

const testing = std.testing;

const TestCtx = struct {
    db: sqlite.Sqlite,
    cfg: handlers.ServerConfig,

    fn init() !TestCtx {
        const db = try sqlite.Sqlite.init(":memory:");
        try migrations.runMigrations(testing.allocator, db);
        const cfg = handlers.ServerConfig{
            .db = db,
            .allocator = testing.allocator,
            .jwt_secret = "test-integration-secret",
            .jwt_expiry = 3600,
            .io = std.testing.io,
        };
        return .{ .db = db, .cfg = cfg };
    }

    fn deinit(self: *TestCtx) void {
        self.db.deinit();
    }

    fn makeParams(self: *TestCtx) std.StringHashMap([]const u8) {
        _ = self;
        return std.StringHashMap([]const u8).init(testing.allocator);
    }
};

fn extractTokenFromBody(body: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, body, "\"token\":\"") orelse return null;
    const val_start = start + "\"token\":\"".len;
    const end = std.mem.indexOfScalarPos(u8, body, val_start, '"') orelse return null;
    return body[val_start..end];
}

fn extractIdFromBody(body: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, body, "\"id\":") orelse return null;
    const val_start = start + "\"id\":".len;
    var end = val_start;
    while (end < body.len and body[end] != '}') : (end += 1) {}
    return body[val_start..end];
}

test "register + login flow" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"alice\",\"password\":\"secret123\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const reg_resp = try handlers.handleRegister(ctx.cfg, req);
    defer reg_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 201), reg_resp.status);
    try testing.expect(std.mem.indexOf(u8, reg_resp.body, "\"user_id\"") != null);
    try testing.expect(std.mem.indexOf(u8, reg_resp.body, "\"token\"") != null);

    const login_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/login",
        .body = "{\"username\":\"alice\",\"password\":\"secret123\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const login_resp = try handlers.handleLogin(ctx.cfg, login_req);
    defer login_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), login_resp.status);
    try testing.expect(std.mem.indexOf(u8, login_resp.body, "\"token\"") != null);
}

test "register duplicate username returns 409" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"bob\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const resp1 = try handlers.handleRegister(ctx.cfg, req);
    defer resp1.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 201), resp1.status);

    const req2 = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"bob\",\"password\":\"pass2\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const result = handlers.handleRegister(ctx.cfg, req2);
    try testing.expectEqual(handlers.HandlerError.DuplicateUsername, result);
}

test "login wrong password returns 401" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const reg_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"charlie\",\"password\":\"correct\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const reg_resp = try handlers.handleRegister(ctx.cfg, reg_req);
    defer reg_resp.deinit(testing.allocator);

    const login_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/login",
        .body = "{\"username\":\"charlie\",\"password\":\"wrong\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const result = handlers.handleLogin(ctx.cfg, login_req);
    try testing.expectEqual(handlers.HandlerError.Unauthorized, result);
}

test "product CRUD" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const reg_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"produser\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const reg_resp = try handlers.handleRegister(ctx.cfg, reg_req);
    defer reg_resp.deinit(testing.allocator);

    const token = extractTokenFromBody(reg_resp.body) orelse return error.Unexpected;
    const user_id = handlers.authenticateRequest(testing.allocator, token, ctx.cfg.jwt_secret) orelse return error.Unexpected;

    const auth_header = try std.fmt.allocPrint(testing.allocator, "Bearer {s}", .{token});
    defer testing.allocator.free(auth_header);

    const create_req = handlers.Request{
        .method = .POST,
        .path = "/api/products",
        .body = "{\"name\":\"Widget\",\"target_price\":9.99}",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const create_resp = try handlers.handleCreateProduct(ctx.cfg, create_req);
    defer create_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 201), create_resp.status);

    const product_id_str = extractIdFromBody(create_resp.body) orelse return error.Unexpected;

    try params.put("id", product_id_str);
    const get_req = handlers.Request{
        .method = .GET,
        .path = "/api/products/:id",
        .body = "",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const get_resp = try handlers.handleGetProduct(ctx.cfg, get_req);
    defer get_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), get_resp.status);
    try testing.expect(std.mem.indexOf(u8, get_resp.body, "Widget") != null);

    const update_req = handlers.Request{
        .method = .PUT,
        .path = "/api/products/:id",
        .body = "{\"name\":\"Super Widget\",\"target_price\":14.99}",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const update_resp = try handlers.handleUpdateProduct(ctx.cfg, update_req);
    defer update_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), update_resp.status);

    const delete_req = handlers.Request{
        .method = .DELETE,
        .path = "/api/products/:id",
        .body = "",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const delete_resp = try handlers.handleDeleteProduct(ctx.cfg, delete_req);
    defer delete_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), delete_resp.status);
}

test "listing CRUD" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const reg_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"listuser\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const reg_resp = try handlers.handleRegister(ctx.cfg, reg_req);
    defer reg_resp.deinit(testing.allocator);

    const token = extractTokenFromBody(reg_resp.body) orelse return error.Unexpected;
    const user_id = handlers.authenticateRequest(testing.allocator, token, ctx.cfg.jwt_secret) orelse return error.Unexpected;
    const auth_header = try std.fmt.allocPrint(testing.allocator, "Bearer {s}", .{token});
    defer testing.allocator.free(auth_header);

    const create_prod_req = handlers.Request{
        .method = .POST,
        .path = "/api/products",
        .body = "{\"name\":\"Gadget\",\"target_price\":19.99}",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const create_prod_resp = try handlers.handleCreateProduct(ctx.cfg, create_prod_req);
    defer create_prod_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 201), create_prod_resp.status);

    const product_id_str = extractIdFromBody(create_prod_resp.body) orelse return error.Unexpected;

    try params.put("id", product_id_str);
    const create_list_req = handlers.Request{
        .method = .POST,
        .path = "/api/products/:id/listings",
        .body = "{\"url\":\"https://example.com/gadget\",\"store_name\":\"ExampleStore\"}",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const create_list_resp = try handlers.handleCreateListing(ctx.cfg, create_list_req);
    defer create_list_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 201), create_list_resp.status);

    const listing_id_str = extractIdFromBody(create_list_resp.body) orelse return error.Unexpected;

    _ = params.remove("id");
    try params.put("id", listing_id_str);
    const get_list_req = handlers.Request{
        .method = .GET,
        .path = "/api/listings/:id",
        .body = "",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const get_list_resp = try handlers.handleGetListing(ctx.cfg, get_list_req);
    defer get_list_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), get_list_resp.status);
    try testing.expect(std.mem.indexOf(u8, get_list_resp.body, "example.com") != null);

    const update_list_req = handlers.Request{
        .method = .PUT,
        .path = "/api/listings/:id",
        .body = "{\"url\":\"https://example.com/gadget-v2\",\"store_name\":\"NewStore\"}",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const update_list_resp = try handlers.handleUpdateListing(ctx.cfg, update_list_req);
    defer update_list_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), update_list_resp.status);

    const del_list_req = handlers.Request{
        .method = .DELETE,
        .path = "/api/listings/:id",
        .body = "",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const del_list_resp = try handlers.handleDeleteListing(ctx.cfg, del_list_req);
    defer del_list_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), del_list_resp.status);
}

test "unauthenticated request to protected route returns 401" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const req = handlers.Request{
        .method = .GET,
        .path = "/api/products",
        .body = "",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const result = handlers.handleListProducts(ctx.cfg, req);
    try testing.expectEqual(handlers.HandlerError.Unauthorized, result);
}

test "forbidden access to other user's product returns 403" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const reg1 = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"owner\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const resp1 = try handlers.handleRegister(ctx.cfg, reg1);
    defer resp1.deinit(testing.allocator);

    const reg2 = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"other\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const resp2 = try handlers.handleRegister(ctx.cfg, reg2);
    defer resp2.deinit(testing.allocator);

    const owner_token = extractTokenFromBody(resp1.body) orelse return error.Unexpected;
    const owner_uid = handlers.authenticateRequest(testing.allocator, owner_token, ctx.cfg.jwt_secret) orelse return error.Unexpected;
    const owner_auth = try std.fmt.allocPrint(testing.allocator, "Bearer {s}", .{owner_token});
    defer testing.allocator.free(owner_auth);

    const create_req = handlers.Request{
        .method = .POST,
        .path = "/api/products",
        .body = "{\"name\":\"Private\",\"target_price\":5.0}",
        .auth_header = owner_auth,
        .user_id = owner_uid,
        .params = &params,
    };
    const create_resp = try handlers.handleCreateProduct(ctx.cfg, create_req);
    defer create_resp.deinit(testing.allocator);

    const product_id_str = extractIdFromBody(create_resp.body) orelse return error.Unexpected;

    const other_token = extractTokenFromBody(resp2.body) orelse return error.Unexpected;
    const other_uid = handlers.authenticateRequest(testing.allocator, other_token, ctx.cfg.jwt_secret) orelse return error.Unexpected;
    const other_auth = try std.fmt.allocPrint(testing.allocator, "Bearer {s}", .{other_token});
    defer testing.allocator.free(other_auth);

    try params.put("id", product_id_str);
    const get_req = handlers.Request{
        .method = .GET,
        .path = "/api/products/:id",
        .body = "",
        .auth_header = other_auth,
        .user_id = other_uid,
        .params = &params,
    };
    const result = handlers.handleGetProduct(ctx.cfg, get_req);
    try testing.expectEqual(handlers.HandlerError.Forbidden, result);
}

test "me endpoint returns user info" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const reg_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"meuser\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const reg_resp = try handlers.handleRegister(ctx.cfg, reg_req);
    defer reg_resp.deinit(testing.allocator);

    const token = extractTokenFromBody(reg_resp.body) orelse return error.Unexpected;
    const user_id = handlers.authenticateRequest(testing.allocator, token, ctx.cfg.jwt_secret) orelse return error.Unexpected;

    const me_req = handlers.Request{
        .method = .GET,
        .path = "/api/auth/me",
        .body = "",
        .auth_header = null,
        .user_id = user_id,
        .params = &params,
    };
    const me_resp = try handlers.handleMe(ctx.cfg, me_req);
    defer me_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), me_resp.status);
    try testing.expect(std.mem.indexOf(u8, me_resp.body, "meuser") != null);
}

test "list products returns empty array" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const reg_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"emptyuser\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const reg_resp = try handlers.handleRegister(ctx.cfg, reg_req);
    defer reg_resp.deinit(testing.allocator);

    const token = extractTokenFromBody(reg_resp.body) orelse return error.Unexpected;
    const user_id = handlers.authenticateRequest(testing.allocator, token, ctx.cfg.jwt_secret) orelse return error.Unexpected;
    const auth_header = try std.fmt.allocPrint(testing.allocator, "Bearer {s}", .{token});
    defer testing.allocator.free(auth_header);

    const list_req = handlers.Request{
        .method = .GET,
        .path = "/api/products",
        .body = "",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const list_resp = try handlers.handleListProducts(ctx.cfg, list_req);
    defer list_resp.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 200), list_resp.status);
    try testing.expectEqualStrings("[]", list_resp.body);
}

test "get nonexistent product returns 404" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const reg_req = handlers.Request{
        .method = .POST,
        .path = "/api/auth/register",
        .body = "{\"username\":\"nfuser\",\"password\":\"pass\"}",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const reg_resp = try handlers.handleRegister(ctx.cfg, reg_req);
    defer reg_resp.deinit(testing.allocator);

    const token = extractTokenFromBody(reg_resp.body) orelse return error.Unexpected;
    const user_id = handlers.authenticateRequest(testing.allocator, token, ctx.cfg.jwt_secret) orelse return error.Unexpected;
    const auth_header = try std.fmt.allocPrint(testing.allocator, "Bearer {s}", .{token});
    defer testing.allocator.free(auth_header);

    try params.put("id", "99999");
    const get_req = handlers.Request{
        .method = .GET,
        .path = "/api/products/:id",
        .body = "",
        .auth_header = auth_header,
        .user_id = user_id,
        .params = &params,
    };
    const result = handlers.handleGetProduct(ctx.cfg, get_req);
    try testing.expectEqual(handlers.HandlerError.NotFound, result);
}

test "healthz and readyz via dispatch" {
    var ctx = try TestCtx.init();
    defer ctx.deinit();

    var params = ctx.makeParams();
    defer params.deinit();

    const req = handlers.Request{
        .method = .GET,
        .path = "/healthz",
        .body = "",
        .auth_header = null,
        .user_id = null,
        .params = &params,
    };
    const h_resp = try handlers.dispatch(ctx.cfg, req, .healthz);
    try testing.expectEqual(@as(u16, 200), h_resp.status);
    try testing.expectEqualStrings("{\"status\":\"ok\"}", h_resp.body);

    const r_resp = try handlers.dispatch(ctx.cfg, req, .readyz);
    try testing.expectEqual(@as(u16, 200), r_resp.status);
    try testing.expectEqualStrings("{\"status\":\"ready\"}", r_resp.body);
}
