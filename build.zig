const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "filter", "Filters for tests.") orelse &.{};

    const test_step = b.step("test", "Run tests.");
    const check_step = b.step("check", "Check step for ZLS.");
    check_step.dependOn(test_step);

    const base58_mod = b.addModule("base58", .{
        .root_source_file = b.path("src/base58.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests_exe = b.addTest(.{
        .root_module = base58_mod,
        .filters = filters,
    });
    b.installArtifact(unit_tests_exe);

    const unit_tests_run = b.addRunArtifact(unit_tests_exe);
    test_step.dependOn(&unit_tests_run.step);
}
