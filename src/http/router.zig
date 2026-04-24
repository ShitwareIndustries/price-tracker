const std = @import("std");

pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,

    pub fn fromString(s: []const u8) ?Method {
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        if (std.mem.eql(u8, s, "PUT")) return .PUT;
        if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, s, "PATCH")) return .PATCH;
        return null;
    }
};

pub const Route = struct {
    method: Method,
    pattern: []const u8,
    handler_id: enum {
        register,
        login,
        me,
        listProducts,
        getProduct,
        createProduct,
        updateProduct,
        deleteProduct,
        listListings,
        getListing,
        createListing,
        updateListing,
        deleteListing,
        listPricesByListing,
        listPricesByProduct,
        healthz,
        readyz,
    },
    require_auth: bool,
};

pub const RouteMatch = struct {
    handler_id: Route.handler_id,
    require_auth: bool,
    params: std.StringHashMap([]const u8),

    pub fn deinit(self: *RouteMatch) void {
        self.params.deinit();
    }
};

pub const Router = struct {
    routes: []const Route,

    pub fn init(routes: []const Route) Router {
        return .{ .routes = routes };
    }

    pub fn match(self: Router, allocator: std.mem.Allocator, method: Method, path: []const u8) ?RouteMatch {
        for (self.routes) |route| {
            if (route.method != method) continue;
            var params = std.StringHashMap([]const u8).init(allocator);
            errdefer params.deinit();
            if (matchPattern(route.pattern, path, &params)) {
                return .{
                    .handler_id = route.handler_id,
                    .require_auth = route.require_auth,
                    .params = params,
                };
            } else {
                params.deinit();
            }
        }
        return null;
    }

    fn matchPattern(pattern: []const u8, path: []const u8, params: *std.StringHashMap([]const u8)) bool {
        const pattern_parts = std.mem.splitSequence(u8, pattern, "/");
        const path_parts = std.mem.splitSequence(u8, path, "/");
        var pat_iter = pattern_parts;
        var path_iter = path_parts;
        while (true) {
            const pat_seg = pat_iter.next() orelse {
                const path_seg = path_iter.next() orelse return true;
                _ = path_seg;
                return false;
            };
            const path_seg = path_iter.next() orelse return false;
            if (pat_seg.len > 0 and pat_seg[0] == ':') {
                const key = pat_seg[1..];
                params.put(key, path_seg) catch return false;
            } else {
                if (!std.mem.eql(u8, pat_seg, path_seg)) return false;
            }
        }
    }
};

pub const default_routes = [_]Route{
    .{ .method = .POST, .pattern = "/api/auth/register", .handler_id = .register, .require_auth = false },
    .{ .method = .POST, .pattern = "/api/auth/login", .handler_id = .login, .require_auth = false },
    .{ .method = .GET, .pattern = "/api/auth/me", .handler_id = .me, .require_auth = true },
    .{ .method = .GET, .pattern = "/api/products", .handler_id = .listProducts, .require_auth = true },
    .{ .method = .POST, .pattern = "/api/products", .handler_id = .createProduct, .require_auth = true },
    .{ .method = .GET, .pattern = "/api/products/:id", .handler_id = .getProduct, .require_auth = true },
    .{ .method = .PUT, .pattern = "/api/products/:id", .handler_id = .updateProduct, .require_auth = true },
    .{ .method = .DELETE, .pattern = "/api/products/:id", .handler_id = .deleteProduct, .require_auth = true },
    .{ .method = .GET, .pattern = "/api/products/:id/listings", .handler_id = .listListings, .require_auth = true },
    .{ .method = .POST, .pattern = "/api/products/:id/listings", .handler_id = .createListing, .require_auth = true },
    .{ .method = .GET, .pattern = "/api/listings/:id", .handler_id = .getListing, .require_auth = true },
    .{ .method = .PUT, .pattern = "/api/listings/:id", .handler_id = .updateListing, .require_auth = true },
    .{ .method = .DELETE, .pattern = "/api/listings/:id", .handler_id = .deleteListing, .require_auth = true },
    .{ .method = .GET, .pattern = "/api/listings/:id/prices", .handler_id = .listPricesByListing, .require_auth = true },
    .{ .method = .GET, .pattern = "/api/products/:id/prices", .handler_id = .listPricesByProduct, .require_auth = true },
    .{ .method = .GET, .pattern = "/healthz", .handler_id = .healthz, .require_auth = false },
    .{ .method = .GET, .pattern = "/readyz", .handler_id = .readyz, .require_auth = false },
};

test "router exact match" {
    const allocator = std.testing.allocator;
    const router = Router.init(&default_routes);
    const m = router.match(allocator, .POST, "/api/auth/register");
    defer if (m) |*match_| match_.deinit();
    try std.testing.expect(m != null);
    try std.testing.expectEqual(Route.handler_id.register, m.?.handler_id);
    try std.testing.expect(!m.?.require_auth);
}

test "router param extraction" {
    const allocator = std.testing.allocator;
    const router = Router.init(&default_routes);
    const m = router.match(allocator, .GET, "/api/products/42");
    defer if (m) |*match_| match_.deinit();
    try std.testing.expect(m != null);
    try std.testing.expectEqual(Route.handler_id.getProduct, m.?.handler_id);
    const id = m.?.params.get("id").?;
    try std.testing.expectEqualStrings("42", id);
}

test "router no match" {
    const allocator = std.testing.allocator;
    const router = Router.init(&default_routes);
    const m = router.match(allocator, .GET, "/api/nonexistent");
    try std.testing.expect(m == null);
}

test "router method mismatch" {
    const allocator = std.testing.allocator;
    const router = Router.init(&default_routes);
    const m = router.match(allocator, .DELETE, "/api/auth/register");
    try std.testing.expect(m == null);
}

test "router nested params" {
    const allocator = std.testing.allocator;
    const router = Router.init(&default_routes);
    const m = router.match(allocator, .GET, "/api/products/7/listings");
    defer if (m) |*match_| match_.deinit();
    try std.testing.expect(m != null);
    try std.testing.expectEqual(Route.handler_id.listListings, m.?.handler_id);
    const id = m.?.params.get("id").?;
    try std.testing.expectEqualStrings("7", id);
}
