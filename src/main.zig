const std = @import("std");
const PEParser = @import("zpe").PEParser;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = std.process.args();
    _ = args.next();

    const file_path = args.next() orelse return error.MissingFilePath;

    var parser = try PEParser.init(allocator, file_path);
    defer parser.deinit();

    try parser.parse();

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    const stdout = bw.writer();

    try parser.print(stdout);

    try bw.flush();
}
