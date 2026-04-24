const std = @import("std");
const sqlite = @import("sqlite.zig");
const data_model = @import("data_model.zig");

pub const MigrationError = error{
    AlreadyApplied,
    RecordFailed,
    VersionMismatch,
};

pub fn runMigrations(db: sqlite.Sqlite) !void {
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS schema_version (
        \\  version INTEGER PRIMARY KEY,
        \\  applied_at INTEGER NOT NULL
        \\);
    );

    const current = try getSchemaVersion(db);
    if (current >= data_model.SCHEMA_VERSION) return;

    const schema_sql = data_model.createSchema();
    try db.execSlice(schema_sql);

    try recordVersion(db, data_model.SCHEMA_VERSION);
}

pub fn getSchemaVersion(db: sqlite.Sqlite) !i64 {
    const result = try db.queryOne(
        std.heap.page_allocator,
        "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
        struct { version: i64 },
        .{},
    );

    if (result) |r| {
        return r.version;
    }
    return 0;
}

fn unixTimestamp() i64 {
    var ts: std.posix.timespec = undefined;
    const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @intCast(ts.sec);
}

fn recordVersion(db: sqlite.Sqlite, version: i64) !void {
    const now = unixTimestamp();
    try db.execBind(
        "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
        .{ version, now },
    );
}
