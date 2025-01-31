const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_step = b.step("test", "Run tests.");

    const base58_mod = b.addModule("base58", .{
        .root_source_file = b.path("src/base58.zig"),
        .target = target,
        .optimize = optimize,
    });
    _ = base58_mod;

    const unit_tests_exe = b.addTest(.{
        .root_source_file = b.path("src/base58.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests_run = b.addRunArtifact(unit_tests_exe);
    test_step.dependOn(&unit_tests_run.step);
}
