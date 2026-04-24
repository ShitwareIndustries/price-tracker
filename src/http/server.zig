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
        const addr = std.net.Address.parseIp("0.0.0.0", self.port) catch |err| return err;
        var server = addr.listen(.{ .reuse_address = true });
        defer server.deinit();
        self.running = true;

        while (self.running) {
            const conn = server.accept() catch |err| {
                if (!self.running) return;
                return err;
            };
            defer conn.stream.close();

            var buf: [4096]u8 = undefined;
            var reader = std.io.bufferedReader(conn.stream.reader());
            var writer = std.io.bufferedWriter(conn.stream.writer());

            const n = reader.reader().read(&buf) catch continue;
            if (n == 0) continue;

            const request_str = buf[0..n];
            const req = parseRequest(self.allocator, request_str) catch continue;
            defer {
                if (req.path) |p| self.allocator.free(p);
                if (req.body) |b| self.allocator.free(b);
                if (req.auth_header) |h| self.allocator.free(h);
            }

            const method = router_mod.Method.fromString(req.method_str orelse "") orelse {
                respondError(&writer, 400, "invalid method") catch continue;
                writer.flush() catch continue;
                continue;
            };

            const path = req.path orelse "/";
            const router_inst = router_mod.Router.init(&router_mod.default_routes);
            var route_match = router_inst.match(self.allocator, method, path);

            const params = if (route_match) |*m| &m.params else blk: {
                const p = std.StringHashMap([]const u8).init(self.allocator);
                break :blk p;
            };
            defer params.deinit();

            if (route_match == null) {
                respondError(&writer, 404, "not found") catch continue;
                writer.flush() catch continue;
                continue;
            }

            var user_id: ?u64 = null;
            if (route_match.?.require_auth) {
                user_id = handlers.authenticateRequest(req.auth_header, self.jwt_secret);
                if (user_id == null) {
                    respondError(&writer, 401, "unauthorized") catch continue;
                    writer.flush() catch continue;
                    if (route_match) |*m| m.deinit();
                    continue;
                }
            }

            const cfg = handlers.ServerConfig{
                .db = self.db,
                .allocator = self.allocator,
                .jwt_secret = self.jwt_secret,
                .jwt_expiry = self.jwt_expiry,
            };

            var handler_params = std.StringHashMap([]const u8).init(self.allocator);
            defer handler_params.deinit();
            if (route_match) |m| {
                var iter = m.params.iterator();
                while (iter.next()) |entry| {
                    handler_params.put(entry.key_ptr.*, entry.value_ptr.*) catch continue;
                } else {}
            }

            const handler_req = handlers.Request{
                .method = method,
                .path = path,
                .body = req.body orelse "",
                .auth_header = req.auth_header,
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
                respondError(&writer, status, msg) catch continue;
                writer.flush() catch continue;
                if (route_match) |*m| m.deinit();
                continue;
            };

            respondJson(&writer, resp.status, resp.body) catch continue;
            if (resp.body.len > 0) self.allocator.free(resp.body);
            writer.flush() catch continue;
            if (route_match) |*m| m.deinit();
        }
    }

    pub fn stop(self: *Server) void {
        self.running = false;
    }

    fn parseRequest(allocator: std.mem.Allocator, raw: []const u8) !ParsedRequest {
        var req = ParsedRequest{
            .method_str = null,
            .path = null,
            .body = null,
            .auth_header = null,
        };

        var lines = std.mem.splitSequence(u8, raw, "\r\n");
        if (lines.next()) |first_line| {
            var parts = std.mem.splitSequence(u8, first_line, " ");
            if (parts.next()) |m| {
                req.method_str = allocator.dupe(u8, m) catch null;
            }
            if (parts.next()) |p| {
                req.path = allocator.dupe(u8, p) catch null;
            }
        }

        var header_end: ?usize = null;
        var i: usize = 0;
        while (i + 3 < raw.len) : (i += 1) {
            if (raw[i] == '\r' and raw[i + 1] == '\n' and raw[i + 2] == '\r' and raw[i + 3] == '\n') {
                header_end = i + 4;
                break;
            }
        }

        if (header_end) |he| {
            if (he < raw.len) {
                const body = raw[he..];
                if (body.len > 0) {
                    req.body = allocator.dupe(u8, body) catch null;
                }
            }
        }

        var header_lines = std.mem.splitSequence(u8, raw, "\r\n");
        _ = header_lines.next();
        while (header_lines.next()) |line| {
            if (line.len == 0) break;
            if (std.mem.startsWith(u8, line, "Authorization: ")) {
                req.auth_header = allocator.dupe(u8, line["Authorization: ".len..]) catch null;
                break;
            }
        }

        return req;
    }

    fn respondJson(writer: anytype, status: u16, body: []const u8) !void {
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
        try writer.writer().print("HTTP/1.1 {} {s}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{s}", .{ status, status_text, body.len, body });
    }

    fn respondError(writer: anytype, status: u16, msg: []const u8) !void {
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
        try writer.writer().print("HTTP/1.1 {} {s}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"error\":\"{s}\"}}", .{ status, status_text, msg.len + 12, msg });
    }
};

const ParsedRequest = struct {
    method_str: ?[]const u8,
    path: ?[]const u8,
    body: ?[]const u8,
    auth_header: ?[]const u8,
};

const HandlerError = handlers.HandlerError;
