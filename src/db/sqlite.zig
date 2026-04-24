const std = @import("std");

const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const Sqlite = struct {
    db: *c.sqlite3,

    pub const OpenError = error{
        OpenFailed,
        ExecFailed,
        PrepareFailed,
        StepFailed,
        BindFailed,
        ColumnAccessFailed,
        OutOfMemory,
    };

    pub fn init(path: [:0]const u8) OpenError!Sqlite {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open_v2(path, &db, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE, null);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return OpenError.OpenFailed;
        }
        return Sqlite{ .db = db.? };
    }

    pub fn deinit(self: *Sqlite) void {
        _ = c.sqlite3_close(self.db);
    }

    pub fn exec(self: Sqlite, sql: [:0]const u8) OpenError!void {
        var err_msg: ?[*:0]u8 = null;
        const rc = c.sqlite3_exec(self.db, sql, null, null, @ptrCast(&err_msg));
        if (rc != c.SQLITE_OK) {
            if (err_msg) |msg| {
                c.sqlite3_free(msg);
            }
            return OpenError.ExecFailed;
        }
    }

    pub fn execSlice(self: Sqlite, allocator: std.mem.Allocator, sql: []const u8) OpenError!void {
        const sentinel = try allocator.allocSentinel(u8, sql.len, 0);
        @memcpy(sentinel[0..sql.len], sql);
        defer allocator.free(sentinel);
        try self.exec(sentinel);
    }

    pub fn enableWalMode(self: Sqlite) OpenError!void {
        try self.exec("PRAGMA journal_mode=WAL;");
    }

    pub fn setBusyTimeout(self: Sqlite, ms: c_int) OpenError!void {
        const rc = c.sqlite3_busy_timeout(self.db, ms);
        if (rc != c.SQLITE_OK) {
            return OpenError.ExecFailed;
        }
    }

    pub fn getJournalMode(self: Sqlite, allocator: std.mem.Allocator) OpenError![]const u8 {
        const sql: [:0]const u8 = "PRAGMA journal_mode;";
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return OpenError.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        const step_rc = c.sqlite3_step(stmt);
        if (step_rc != c.SQLITE_ROW) return OpenError.StepFailed;

        const text = c.sqlite3_column_text(stmt, 0);
        const len = c.sqlite3_column_bytes(stmt, 0);
        return try allocator.dupe(u8, text[0..@intCast(len)]);
    }

    pub fn getLastInsertRowId(self: Sqlite) i64 {
        return c.sqlite3_last_insert_rowid(self.db);
    }

    pub fn getChanges(self: Sqlite) u64 {
        return @intCast(c.sqlite3_changes(self.db));
    }

    pub fn queryOne(
        self: Sqlite,
        allocator: std.mem.Allocator,
        sql: [:0]const u8,
        comptime T: type,
        binds: anytype,
    ) OpenError!?T {
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return OpenError.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        try bindParams(stmt.?, binds);

        const step_rc = c.sqlite3_step(stmt);
        if (step_rc == c.SQLITE_DONE) return null;
        if (step_rc != c.SQLITE_ROW) return OpenError.StepFailed;

        return try readRow(allocator, stmt.?, T);
    }

    pub fn queryAll(
        self: Sqlite,
        allocator: std.mem.Allocator,
        sql: [:0]const u8,
        comptime T: type,
        binds: anytype,
    ) OpenError![]T {
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return OpenError.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        try bindParams(stmt.?, binds);

        var results: std.ArrayList(T) = .empty;
        errdefer {
            for (results.items) |item| {
                freeRow(allocator, T, item);
            }
            results.deinit(allocator);
        }

        while (true) {
            const step_rc = c.sqlite3_step(stmt);
            if (step_rc == c.SQLITE_DONE) break;
            if (step_rc != c.SQLITE_ROW) return OpenError.StepFailed;

            const row = try readRow(allocator, stmt.?, T);
            try results.append(allocator, row);
        }

        return results.toOwnedSlice(allocator);
    }

    pub fn execBind(self: Sqlite, sql: [:0]const u8, binds: anytype) OpenError!void {
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK) return OpenError.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        try bindParams(stmt.?, binds);

        const step_rc = c.sqlite3_step(stmt);
        if (step_rc != c.SQLITE_DONE and step_rc != c.SQLITE_ROW) {
            return OpenError.StepFailed;
        }
    }

    fn bindParams(stmt: *c.sqlite3_stmt, binds: anytype) OpenError!void {
        const fields = std.meta.fields(@TypeOf(binds));
        inline for (fields, 1..) |field, i| {
            const val = @field(binds, field.name);
            const rc = bindValue(stmt, @intCast(i), val);
            if (rc != c.SQLITE_OK) return OpenError.BindFailed;
        }
    }

    fn bindValue(stmt: *c.sqlite3_stmt, idx: c_int, val: anytype) c_int {
        return switch (@TypeOf(val)) {
            i64 => c.sqlite3_bind_int64(stmt, idx, val),
            u64 => c.sqlite3_bind_int64(stmt, idx, @as(i64, @intCast(val))),
            i32 => c.sqlite3_bind_int(stmt, idx, val),
            u32 => c.sqlite3_bind_int64(stmt, idx, @as(i64, @intCast(val))),
            f64 => c.sqlite3_bind_double(stmt, idx, val),
            bool => c.sqlite3_bind_int(stmt, idx, if (val) 1 else 0),
            []const u8, [:0]const u8 => c.sqlite3_bind_text(stmt, idx, val.ptr, @intCast(val.len), c.SQLITE_TRANSIENT),
            ?[]const u8, ?[:0]const u8 => if (val) |v| c.sqlite3_bind_text(stmt, idx, v.ptr, @intCast(v.len), c.SQLITE_TRANSIENT) else c.sqlite3_bind_null(stmt, idx),
            ?i64 => if (val) |v| c.sqlite3_bind_int64(stmt, idx, v) else c.sqlite3_bind_null(stmt, idx),
            ?f64 => if (val) |v| c.sqlite3_bind_double(stmt, idx, v) else c.sqlite3_bind_null(stmt, idx),
            ?i32 => if (val) |v| c.sqlite3_bind_int(stmt, idx, v) else c.sqlite3_bind_null(stmt, idx),
            else => @compileError("Unsupported bind type: " ++ @typeName(@TypeOf(val))),
        };
    }

    fn readRow(allocator: std.mem.Allocator, stmt: *c.sqlite3_stmt, comptime T: type) OpenError!T {
        var result: T = undefined;
        const fields = std.meta.fields(T);
        inline for (fields, 0..) |field, i| {
            @field(result, field.name) = try readColumn(allocator, stmt, @intCast(i), field.type);
        }
        return result;
    }

    fn readColumn(allocator: std.mem.Allocator, stmt: *c.sqlite3_stmt, idx: c_int, comptime T: type) OpenError!T {
        return switch (T) {
            u64 => @intCast(c.sqlite3_column_int64(stmt, idx)),
            i64 => c.sqlite3_column_int64(stmt, idx),
            u32 => @intCast(c.sqlite3_column_int(stmt, idx)),
            i32 => c.sqlite3_column_int(stmt, idx),
            f64 => c.sqlite3_column_double(stmt, idx),
            bool => c.sqlite3_column_int(stmt, idx) != 0,
            []const u8 => blk: {
                const text = c.sqlite3_column_text(stmt, idx);
                const len = c.sqlite3_column_bytes(stmt, idx);
                break :blk try allocator.dupe(u8, text[0..@intCast(len)]);
            },
            ?[]const u8 => blk: {
                if (c.sqlite3_column_type(stmt, idx) == c.SQLITE_NULL) {
                    break :blk null;
                }
                const text = c.sqlite3_column_text(stmt, idx);
                const len = c.sqlite3_column_bytes(stmt, idx);
                break :blk try allocator.dupe(u8, text[0..@intCast(len)]);
            },
            ?i64 => blk: {
                if (c.sqlite3_column_type(stmt, idx) == c.SQLITE_NULL) {
                    break :blk null;
                }
                break :blk c.sqlite3_column_int64(stmt, idx);
            },
            ?f64 => blk: {
                if (c.sqlite3_column_type(stmt, idx) == c.SQLITE_NULL) {
                    break :blk null;
                }
                break :blk c.sqlite3_column_double(stmt, idx);
            },
            ?i32 => blk: {
                if (c.sqlite3_column_type(stmt, idx) == c.SQLITE_NULL) {
                    break :blk null;
                }
                break :blk c.sqlite3_column_int(stmt, idx);
            },
            else => @compileError("Unsupported read type: " ++ @typeName(T)),
        };
    }

    fn freeRow(allocator: std.mem.Allocator, comptime T: type, row: T) void {
        const fields = std.meta.fields(T);
        inline for (fields) |field| {
            switch (field.type) {
                []const u8 => allocator.free(@field(row, field.name)),
                ?[]const u8 => if (@field(row, field.name)) |v| allocator.free(v),
                else => {},
            }
        }
    }
};
