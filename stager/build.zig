const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .gnu,
    });

    const exe = b.addExecutable(.{
        .name = "stager",
        .root_module = b.createModule(.{
            .root_source_file = b.path("stager_build.zig"),
            .target = target,
            .optimize = .ReleaseSmall,
            .strip = true,
        }),
    });

    exe.subsystem = .Windows;
    exe.linkSystemLibrary("winhttp");
    exe.linkSystemLibrary("kernel32");

    b.installArtifact(exe);
}
