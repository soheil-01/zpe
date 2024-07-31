const std = @import("std");
const win32 = @import("zigwin32").everything;

const assert = std.debug.assert;

pub const PEParser = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    file: std.fs.File,
    dos_header: ?win32.IMAGE_DOS_HEADER = null,

    // TODO: file path or file content
    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !Self {

        // TODO: keeping the file open until the parser is deinitialized or creating a copy of the file content
        const file = try std.fs.cwd().openFile(file_path, .{});

        return .{
            .allocator = allocator,
            .file = file,
        };
    }

    pub fn deinit(self: Self) void {
        self.file.close();
    }

    pub fn parse(self: *Self) !void {
        try self.parseDOSHeader();
    }

    fn parseDOSHeader(self: *Self) !void {
        // TODO: is it required to seek to 0?
        try self.file.seekTo(0);

        // TODO: keep the file.reader() as the struct member
        const reader = self.file.reader();

        const dos_header = try reader.readStruct(win32.IMAGE_DOS_HEADER);
        if (dos_header.e_magic != win32.IMAGE_DOS_SIGNATURE) return error.InvalidDOSHeaderMagic;

        self.dos_header = dos_header;
    }

    pub fn print(self: Self, writer: anytype) !void {
        try self.printDOSHeaderInfo(writer);
    }

    fn printDOSHeaderInfo(self: Self, writer: anytype) !void {
        assert(self.dos_header != null);
        const dos_header = self.dos_header.?;

        try writer.writeAll("DOS Header:\n");
        try writer.writeAll("-----------\n\n");

        try writer.print("Magic: 0x{X}\n", .{dos_header.e_magic});
        try writer.print("File address of new exe header: 0x{X}\n", .{dos_header.e_lfanew});
    }
};
