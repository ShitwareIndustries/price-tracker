const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sqlite_dep = b.dependency("sqlite3", .{
        .target = target,
        .optimize = optimize,
    });
    const json5_dep = b.dependency("json5", .{
        .target = target,
        .optimize = optimize,
    });

    const module = b.addModule("price_tracker", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("sqlite3", sqlite_dep.module("sqlite3"));
    module.addImport("json5", json5_dep.module("json5"));

    // Main executable
    const exe = b.addExecutable(.{
        .name = "price_tracker",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("price_tracker", module);
    exe.linkLibrary(sqlite_dep.artifact("sqlite3"));
    b.installArtifact(exe);

    // Tests
    const test_step = b.step("test", "Run tests");
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.addModule("price_tracker", module);
    unit_tests.linkLibrary(sqlite_dep.artifact("sqlite3"));

    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // HTTP test
    const http_test = b.addTest(.{
        .root_source_file = b.path("test/http_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    http_test.addModule("price_tracker", module);
    http_test.linkLibrary(sqlite_dep.artifact("sqlite3"));
    const run_http_test = b.addRunArtifact(http_test);
    test_step.dependOn(&run_http_test.step);

    // Scraper test
    const scraper_test = b.addTest(.{
        .root_source_file = b.path("test/scraper_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    scraper_test.addModule("price_tracker", module);
    scraper_test.linkLibrary(sqlite_dep.artifact("sqlite3"));
    const run_scraper_test = b.addRunArtifact(scraper_test);
    test_step.dependOn(&run_scraper_test.step);

    // DB test
    const db_test = b.addTest(.{
        .root_source_file = b.path("test/db_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_test.addModule("price_tracker", module);
    db_test.linkLibrary(sqlite_dep.artifact("sqlite3"));
    const run_db_test = b.addRunArtifact(db_test);
    test_step.dependOn(&run_db_test.step);

    // Unit price test
    const unit_price_test = b.addTest(.{
        .root_source_file = b.path("test/unit_price_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_price_test.addModule("price_tracker", module);
    unit_price_test.linkLibrary(sqlite_dep.artifact("sqlite3"));
    const run_unit_price_test = b.addRunArtifact(unit_price_test);
    test_step.dependOn(&run_unit_price_test.step);
}
