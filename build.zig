const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("gui/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "peer-transfer-gui",
        .root_module = exe_mod,
    });

    exe_mod.addCSourceFile(.{ 
        .file = b.path("src/transfer.c"), 
        .flags = &.{ "-Dmain=backend_main", "-Wno-implicit-function-declaration" } 
    });
    
    exe_mod.addIncludePath(b.path("."));
    exe_mod.addIncludePath(b.path("lib"));
    
    exe_mod.addIncludePath(.{ .cwd_relative = "/usr/include" });
    
    exe.linkSystemLibrary("sdl3");
    exe.linkSystemLibrary("sdl3-ttf");

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}