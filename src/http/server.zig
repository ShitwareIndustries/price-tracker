// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025 Price Tracker Contributors

const std = @import("std");
const router_mod = @import("router.zig");
const handlers = @import("handlers.zig");
const jwt_mod = @import("../auth/jwt.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    port: u16,
    db: @import("../db/sqlite.zig").Sqlite,
    jwt_secret: []const u8,
    jwt_expiry: u32,
    running: bool,

    pub fn init(allocator: std.mem.Allocator, port: u16, db: @import("../db/sqlite.zig").Sqlite, jwt_secret: []const u8) Server {
        return .{
            .allocator = allocator,
            .port = port,
            .db = db,
            .jwt_secret = jwt_secret,
            .jwt_expiry = 86400,
            .running = false,
        };
    }

    pub fn start(self: *Server) !void {
        var threaded: std.Io.Threaded = .init_single_threaded;
        const io = threaded.io();

        const addr = try std.Io.net.IpAddress.parseIp4("0.0.0.0", self.port);
        var server = try addr.listen(io, .{ .reuse_address = true });
        defer server.deinit(io);
        self.running = true;

        while (self.running) {
            const stream = server.accept(io) catch |err| {
                if (!self.running) return;
                return err;
            };
            defer stream.close(io);

            var read_buf: [8192]u8 = undefined;
            var write_buf: [8192]u8 = undefined;

            var net_reader = stream.reader(io, &read_buf);
            var net_writer = stream.writer(io, &write_buf);

            var http_server = std.http.Server.init(&net_reader.interface, &net_writer.interface);
            var request = http_server.receiveHead() catch continue;
            const head = request.head;

            const method = router_mod.Method.fromString(@tagName(head.method)) orelse {
                respondError(&net_writer.interface, 400, "invalid method") catch continue;
                net_writer.interface.flush() catch continue;
                continue;
            };

            const path = head.target;

            const auth_header: ?[]const u8 = blk: {
                var auth_val: ?[]const u8 = null;
                var it = request.iterateHeaders();
                while (it.next()) |hdr| {
                    if (std.ascii.eqlIgnoreCase(hdr.name, "authorization")) {
                        auth_val = hdr.value;
                        break;
                    }
                }
                break :blk auth_val;
            };

            const body: []const u8 = blk: {
                if (!head.method.requestHasBody()) break :blk "";
                const content_length = head.content_length orelse break :blk "";
                if (content_length == 0) break :blk "";
                if (content_length > 1048576) break :blk "";
                const body_buf = self.allocator.alloc(u8, @intCast(content_length)) catch break :blk "";
                errdefer self.allocator.free(body_buf);
                var body_read_buf: [4096]u8 = undefined;
                const body_reader = request.readerExpectNone(&body_read_buf);
                body_reader.readAll(body_buf) catch break :blk "";
                break :blk body_buf;
            };

            const router_inst = router_mod.Router.init(&router_mod.default_routes);
            var route_match = router_inst.match(self.allocator, method, path);

            var params = if (route_match) |*m|
                m.params
            else
                std.StringHashMap([]const u8).init(self.allocator);
            defer params.deinit();

            if (route_match == null) {
                respondError(&net_writer.interface, 404, "not found") catch continue;
                net_writer.interface.flush() catch continue;
                if (body.len > 0) self.allocator.free(body);
                continue;
            }

            var user_id: ?u64 = null;
            if (route_match.?.require_auth) {
                user_id = handlers.authenticateRequest(self.allocator, auth_header, self.jwt_secret);
                if (user_id == null) {
                    respondError(&net_writer.interface, 401, "unauthorized") catch continue;
                    net_writer.interface.flush() catch continue;
                    if (route_match) |*m| m.deinit();
                    if (body.len > 0) self.allocator.free(body);
                    continue;
                }
            }

            const cfg = handlers.ServerConfig{
                .db = self.db,
                .allocator = self.allocator,
                .jwt_secret = self.jwt_secret,
                .jwt_expiry = self.jwt_expiry,
                .io = io,
            };

            var handler_params = std.StringHashMap([]const u8).init(self.allocator);
            defer handler_params.deinit();
            if (route_match) |m| {
                var iter = m.params.iterator();
                while (iter.next()) |entry| {
                    handler_params.put(entry.key_ptr.*, entry.value_ptr.*) catch continue;
                }
            }

            const handler_req = handlers.Request{
                .method = method,
                .path = path,
                .body = body,
                .auth_header = auth_header,
                .user_id = user_id,
                .params = &handler_params,
            };

            const resp = handlers.dispatch(cfg, handler_req, route_match.?.handler_id) catch |err| {
                const status: u16 = switch (err) {
                    HandlerError.Unauthorized => 401,
                    HandlerError.Forbidden => 403,
                    HandlerError.BadRequest => 400,
                    HandlerError.NotFound => 404,
                    HandlerError.InternalError => 500,
                    HandlerError.DuplicateUsername => 409,
                    else => 500,
                };
                const msg = switch (err) {
                    HandlerError.Unauthorized => "unauthorized",
                    HandlerError.Forbidden => "forbidden",
                    HandlerError.BadRequest => "bad request",
                    HandlerError.NotFound => "not found",
                    HandlerError.InternalError => "internal error",
                    HandlerError.DuplicateUsername => "duplicate username",
                    else => "internal error",
                };
                respondError(&net_writer.interface, status, msg) catch continue;
                net_writer.interface.flush() catch continue;
                if (route_match) |*m| m.deinit();
                if (body.len > 0) self.allocator.free(body);
                continue;
            };

            respondJson(&net_writer.interface, resp.status, resp.body) catch continue;
            if (resp.body.len > 0) self.allocator.free(resp.body);
            net_writer.interface.flush() catch continue;
            if (route_match) |*m| m.deinit();
            if (body.len > 0) self.allocator.free(body);
        }
    }

    pub fn stop(self: *Server) void {
        self.running = false;
    }

    fn respondJson(writer: *std.Io.Writer, status: u16, body: []const u8) !void {
        const status_text = switch (status) {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            409 => "Conflict",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            else => "Unknown",
        };
        try writer.print("HTTP/1.1 {} {s}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{s}", .{ status, status_text, body.len, body });
    }

    fn respondError(writer: *std.Io.Writer, status: u16, msg: []const u8) !void {
        const status_text = switch (status) {
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            409 => "Conflict",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            else => "Unknown",
        };
        try writer.print("HTTP/1.1 {} {s}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"error\":\"{s}\"}}", .{ status, status_text, msg.len + 11, msg });
    }
};

const HandlerError = handlers.HandlerError;
