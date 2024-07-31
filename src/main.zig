const std = @import("std");
const zpe = @import("zpe");

pub fn main() !void {
    var args = std.process.args();
    _ = args.next();

    const file_name = args.next() orelse "";

    std.debug.print("file name: {s}\n", .{file_name});

    const file = try std.fs.cwd().openFile(file_name, .{});
    defer file.close();
}
