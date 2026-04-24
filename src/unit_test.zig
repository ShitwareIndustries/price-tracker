// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2025 Price Tracker Contributors

const std = @import("std");

pub const auth_jwt = @import("auth/jwt.zig");
pub const auth_password = @import("auth/password.zig");
pub const http_router = @import("http/router.zig");
pub const http_handlers = @import("http/handlers.zig");

pub fn main(init: std.process.Init) !void {
    _ = init;
}
