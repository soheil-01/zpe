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

        try writer.print("  Magic number: 0x{X}\n", .{dos_header.e_magic});
        try writer.print("  Bytes on last page of file: 0x{X}\n", .{dos_header.e_cblp});
        try writer.print("  Pages in file: 0x{X}\n", .{dos_header.e_cp});
        try writer.print("  Relocations: 0x{X}\n", .{dos_header.e_crlc});
        try writer.print("  Size of header in paragraphs: 0x{X}\n", .{dos_header.e_cparhdr});
        try writer.print("  Minimum extra paragraphs needed: 0x{X}\n", .{dos_header.e_minalloc});
        try writer.print("  Maximum extra paragraphs needed: 0x{X}\n", .{dos_header.e_maxalloc});
        try writer.print("  Initial (relative) SS value: 0x{X}\n", .{dos_header.e_ss});
        try writer.print("  Initial SP value: 0x{X}\n", .{dos_header.e_sp});
        try writer.print("  Checksum: 0x{X}\n", .{dos_header.e_csum});
        try writer.print("  Initial IP value: 0x{X}\n", .{dos_header.e_ip});
        try writer.print("  Initial (relative) CS value: 0x{X}\n", .{dos_header.e_cs});
        try writer.print("  File address of relocation table: 0x{X}\n", .{dos_header.e_lfarlc});
        try writer.print("  Overlay number: 0x{X}\n", .{dos_header.e_ovno});

        try writer.writeAll("  Reserved words[4]: ");
        for (dos_header.e_res, 0..) |item, index| {
            try writer.print("0x{X}", .{item});
            if (index < dos_header.e_res.len - 1) {
                try writer.writeAll(", ");
            }
        }
        try writer.writeAll("\n");

        try writer.print("  OEM identifier: 0x{X}\n", .{dos_header.e_oemid});
        try writer.print("  OEM information: 0x{X}\n", .{dos_header.e_oeminfo});

        try writer.writeAll("  Reserved words[10]: ");
        for (dos_header.e_res2, 0..) |item, index| {
            try writer.print("0x{X}", .{item});
            if (index < dos_header.e_res2.len - 1) {
                try writer.writeAll(", ");
            }
        }
        try writer.writeAll("\n");

        try writer.print("  File address of new exe header: 0x{X}\n", .{dos_header.e_lfanew});
    }
};
