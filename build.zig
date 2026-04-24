const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sqlite_dep = b.dependency("sqlite3", .{
        .target = target,
        .optimize = optimize,
    });

    const sqlite3_lib = sqlite_dep.artifact("sqlite3");

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_mod.linkLibrary(sqlite3_lib);

    const exe = b.addExecutable(.{
        .name = "price_tracker",
        .root_module = root_mod,
    });
    b.installArtifact(exe);

    const test_step = b.step("test", "Run all tests");

    const unit_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_mod.linkLibrary(sqlite3_lib);
    const unit_tests = b.addTest(.{
        .root_module = unit_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    const db_mod = b.createModule(.{
        .root_source_file = b.path("src/db/db_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_mod.linkLibrary(sqlite3_lib);
    const db_test = b.addTest(.{
        .root_module = db_mod,
    });
    const run_db_test = b.addRunArtifact(db_test);
    test_step.dependOn(&run_db_test.step);
}
