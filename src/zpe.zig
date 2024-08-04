const std = @import("std");
const win32 = @import("zigwin32").everything;
const datetime = @import("zig-datetime").datetime;
const assert = std.debug.assert;

pub const PEParser = struct {
    const Self = @This();

    const RICH_HEADER_ENTRY = struct {
        build_id: u16,
        product_id: u16,
        use_count: u32,
    };

    allocator: std.mem.Allocator,
    file: std.fs.File,
    dos_header: ?win32.IMAGE_DOS_HEADER = null,
    rich_header_entries: ?[]RICH_HEADER_ENTRY = null,
    nt_headers_32: ?win32.IMAGE_NT_HEADERS32 = null,
    nt_headers_64: ?win32.IMAGE_NT_HEADERS64 = null,
    is_64bit: bool = false,

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
        if (self.rich_header_entries) |rich_header_entries| self.allocator.free(rich_header_entries);
    }

    pub fn parse(self: *Self) !void {
        try self.parseDOSHeader();
        try self.parseRichHeader();
        try self.parseNTHeaders();
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

    fn parseRichHeader(self: *Self) !void {
        assert(self.dos_header != null);

        const dos_header = self.dos_header.?;

        try self.file.seekTo(0);

        const reader = self.file.reader();

        var buffer = try self.allocator.alloc(u8, @intCast(dos_header.e_lfanew));
        defer self.allocator.free(buffer);

        try reader.readNoEof(buffer);

        const rich_id_index = std.mem.indexOf(u8, buffer, "Rich") orelse return;

        const checksum_text = buffer[rich_id_index + 4 .. rich_id_index + 8];
        const checksum_mask = "DanS";

        var start_marker: [4]u8 = undefined;
        for (0..4) |byte_index| start_marker[byte_index] = checksum_text[byte_index] ^ checksum_mask[byte_index];

        const rich_header_start_index = std.mem.indexOf(u8, buffer, &start_marker) orelse return;

        const rich_header_payload = buffer[rich_header_start_index + 16 .. rich_id_index];

        // TODO: is it required to check the entries length?
        assert(rich_header_payload.len % 8 == 0);

        var rich_header_entries = try self.allocator.alloc(RICH_HEADER_ENTRY, rich_header_payload.len / 8);

        var entry_offset: usize = 0;
        while (entry_offset < rich_header_payload.len) : (entry_offset += 8) {
            var encrypted_comp_id = rich_header_payload[entry_offset .. entry_offset + 4];
            for (0..4) |byte_index| encrypted_comp_id[byte_index] = encrypted_comp_id[byte_index] ^ checksum_text[byte_index];

            var encrypted_count = rich_header_payload[entry_offset + 4 .. entry_offset + 8];
            for (0..4) |byte_index| encrypted_count[byte_index] = encrypted_count[byte_index] ^ checksum_text[byte_index];

            const build_id = std.mem.readInt(u16, encrypted_comp_id[0..2], .little);
            const product_id = std.mem.readInt(u16, encrypted_comp_id[2..4], .little);
            const use_count = std.mem.readInt(u32, encrypted_count[0..4], .little);

            rich_header_entries[entry_offset / 8] = .{
                .build_id = build_id,
                .product_id = product_id,
                .use_count = use_count,
            };
        }

        self.rich_header_entries = rich_header_entries;
    }

    fn parseNTHeaders(self: *Self) !void {
        assert(self.dos_header != null);

        const e_lfanew = self.dos_header.?.e_lfanew;
        try self.file.seekTo(@intCast(e_lfanew + @sizeOf(std.os.windows.DWORD) + @sizeOf(win32.IMAGE_FILE_HEADER)));

        const reader = self.file.reader();

        const optional_header_magic = try reader.readEnum(win32.IMAGE_OPTIONAL_HEADER_MAGIC, .little);
        self.is_64bit = if (optional_header_magic == .NT_OPTIONAL_HDR_MAGIC) true else false;

        try self.file.seekTo(@intCast(e_lfanew));

        if (self.is_64bit) {
            self.nt_headers_64 = try reader.readStruct(win32.IMAGE_NT_HEADERS64);
        } else {
            self.nt_headers_32 = try reader.readStruct(win32.IMAGE_NT_HEADERS32);
        }
    }

    pub fn print(self: Self, writer: anytype) !void {
        try self.printDOSHeaderInfo(writer);
        try writer.writeAll("\n");
        try self.printRichHeaderInfo(writer);
        try writer.writeAll("\n");
        try self.printNTHeadersInfo(writer);
        try writer.writeAll("\n");
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

    fn printRichHeaderInfo(self: Self, writer: anytype) !void {
        const rich_header_entries = self.rich_header_entries orelse return;

        try writer.writeAll("Rich Header:\n");
        try writer.writeAll("------------\n\n");

        for (rich_header_entries) |entry| {
            try writer.print(" 0x{X:0>4} 0x{X:0>4} 0x{X:0>8}: {d}.{d}.{d}\n", .{ entry.build_id, entry.product_id, entry.use_count, entry.build_id, entry.product_id, entry.use_count });
        }
    }

    fn printNTHeadersInfo(self: Self, writer: anytype) !void {
        try writer.writeAll("NT Headers:\n");
        try writer.writeAll("------------\n\n");

        if (self.is_64bit) {
            try self.printNTHeaders64Info(writer);
        } else {
            try self.printNTHeaders32Info(writer);
        }
    }

    fn printNTHeaders32Info(self: Self, writer: anytype) !void {
        assert(self.nt_headers_32 != null);
        const nt_headers = self.nt_headers_32.?;

        try writer.print("  PE Signature: 0x{X}\n", .{nt_headers.Signature});

        try writer.writeAll("\nFile Header:\n\n");
        try writer.print("  Machine: {s} (0x{X})\n", .{ @tagName(nt_headers.FileHeader.Machine), @intFromEnum(nt_headers.FileHeader.Machine) });
        try writer.print("  Number of sections: {}\n", .{nt_headers.FileHeader.NumberOfSections});

        const time_date_string = try datetime.Datetime.fromSeconds(@floatFromInt(nt_headers.FileHeader.TimeDateStamp)).formatHttp(self.allocator);
        defer self.allocator.free(time_date_string);
        try writer.print("  Time date stamp: 0x{X} ({s})\n", .{ nt_headers.FileHeader.TimeDateStamp, time_date_string });

        try writer.print("  Pointer to symbol table: 0x{X}\n", .{nt_headers.FileHeader.PointerToSymbolTable});
        try writer.print("  Number of symbols: {}\n", .{nt_headers.FileHeader.NumberOfSymbols});
        try writer.print("  Size of optional header: {}\n", .{nt_headers.FileHeader.SizeOfOptionalHeader});

        try writer.print("  Characteristics: 0x{X}\n", .{@as(u16, @bitCast(nt_headers.FileHeader.Characteristics))});
        inline for (std.meta.fields(win32.IMAGE_FILE_CHARACTERISTICS)) |field| {
            const value = @field(nt_headers.FileHeader.Characteristics, field.name);
            if (field.name[0] != '_' and value == 1) {
                try writer.print("      {s}\n", .{field.name});
            }
        }

        try writer.writeAll("\nOptional Header:\n\n");
        try writer.print("  Magic: 0x{X}\n", .{@intFromEnum(nt_headers.OptionalHeader.Magic)});
        try writer.print("  Major linker version: {}\n", .{nt_headers.OptionalHeader.MajorLinkerVersion});
        try writer.print("  Minor linker version: {}\n", .{nt_headers.OptionalHeader.MinorLinkerVersion});
        try writer.print("  Size of code: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfCode});
        try writer.print("  Size of initialized data: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfInitializedData});
        try writer.print("  Size of uninitialized data: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfUninitializedData});
        try writer.print("  Address of entry point: 0x{X}\n", .{nt_headers.OptionalHeader.AddressOfEntryPoint});
        try writer.print("  Base of code: 0x{X}\n", .{nt_headers.OptionalHeader.BaseOfCode});
        try writer.print("  Base of data: 0x{X}\n", .{nt_headers.OptionalHeader.BaseOfData});
        try writer.print("  Image base: 0x{X}\n", .{nt_headers.OptionalHeader.ImageBase});
        try writer.print("  Section alignment: 0x{X}\n", .{nt_headers.OptionalHeader.SectionAlignment});
        try writer.print("  File alignment: 0x{X}\n", .{nt_headers.OptionalHeader.FileAlignment});
        try writer.print("  Major operating system version: {}\n", .{nt_headers.OptionalHeader.MajorOperatingSystemVersion});
        try writer.print("  Minor operating system version: {}\n", .{nt_headers.OptionalHeader.MinorOperatingSystemVersion});
        try writer.print("  Major image version: {}\n", .{nt_headers.OptionalHeader.MajorImageVersion});
        try writer.print("  Minor image version: {}\n", .{nt_headers.OptionalHeader.MinorImageVersion});
        try writer.print("  Major subsystem version: {}\n", .{nt_headers.OptionalHeader.MajorSubsystemVersion});
        try writer.print("  Minor subsystem version: {}\n", .{nt_headers.OptionalHeader.MinorSubsystemVersion});
        try writer.print("  Win32 version value: 0x{X}\n", .{nt_headers.OptionalHeader.Win32VersionValue});
        try writer.print("  Size of image: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfImage});
        try writer.print("  Size of headers: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfHeaders});
        try writer.print("  CheckSum: 0x{X}\n", .{nt_headers.OptionalHeader.CheckSum});
        try writer.print("  Subsystem: {s} (0x{X})\n", .{ @tagName(nt_headers.OptionalHeader.Subsystem), @intFromEnum(nt_headers.OptionalHeader.Subsystem) });
        try writer.print("  DLL characteristics: 0x{X}\n", .{@as(u16, @bitCast(nt_headers.OptionalHeader.DllCharacteristics))});
        try writer.print("  Size of stack reserve: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfStackReserve});
        try writer.print("  Size of stack commit: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfStackCommit});
        try writer.print("  Size of heap reserve: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfHeapReserve});
        try writer.print("  Size of heap commit: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfHeapCommit});
        try writer.print("  Loader flags: 0x{X}\n", .{nt_headers.OptionalHeader.LoaderFlags});
        try writer.print("  Number of RVA and sizes: {}\n", .{nt_headers.OptionalHeader.NumberOfRvaAndSizes});

        try writer.writeAll("\nData Directories:\n\n");
        inline for (std.meta.fields(win32.IMAGE_DIRECTORY_ENTRY)) |entry| {
            const data_directory = nt_headers.OptionalHeader.DataDirectory[entry.value];

            try writer.print("\n    * {s} Directory:\n", .{entry.name});
            try writer.print("      RVA: 0x{X}\n", .{data_directory.VirtualAddress});
            try writer.print("      Size: 0x{X}\n", .{data_directory.Size});
        }
    }

    fn printNTHeaders64Info(self: Self, writer: anytype) !void {
        assert(self.nt_headers_64 != null);
        const nt_headers = self.nt_headers_64.?;

        try writer.print("  PE Signature: 0x{X}\n", .{nt_headers.Signature});

        try writer.writeAll("\nFile Header:\n\n");
        try writer.print("  Machine: {s} (0x{X})\n", .{ @tagName(nt_headers.FileHeader.Machine), @intFromEnum(nt_headers.FileHeader.Machine) });
        try writer.print("  Number of sections: {}\n", .{nt_headers.FileHeader.NumberOfSections});

        const time_date_string = try datetime.Datetime.fromSeconds(@floatFromInt(nt_headers.FileHeader.TimeDateStamp)).formatHttp(self.allocator);
        defer self.allocator.free(time_date_string);
        try writer.print("  Time date stamp: 0x{X} ({s})\n", .{ nt_headers.FileHeader.TimeDateStamp, time_date_string });

        try writer.print("  Pointer to symbol table: 0x{X}\n", .{nt_headers.FileHeader.PointerToSymbolTable});
        try writer.print("  Number of symbols: {}\n", .{nt_headers.FileHeader.NumberOfSymbols});
        try writer.print("  Size of optional header: {}\n", .{nt_headers.FileHeader.SizeOfOptionalHeader});

        try writer.print("  Characteristics: 0x{X}\n", .{@as(u16, @bitCast(nt_headers.FileHeader.Characteristics))});
        inline for (std.meta.fields(win32.IMAGE_FILE_CHARACTERISTICS)) |field| {
            const value = @field(nt_headers.FileHeader.Characteristics, field.name);
            if (field.name[0] != '_' and value == 1) {
                try writer.print("      {s}\n", .{field.name});
            }
        }

        try writer.writeAll("\nOptional Header:\n\n");
        try writer.print("  Magic: 0x{X}\n", .{@intFromEnum(nt_headers.OptionalHeader.Magic)});
        try writer.print("  Major linker version: {}\n", .{nt_headers.OptionalHeader.MajorLinkerVersion});
        try writer.print("  Minor linker version: {}\n", .{nt_headers.OptionalHeader.MinorLinkerVersion});
        try writer.print("  Size of code: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfCode});
        try writer.print("  Size of initialized data: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfInitializedData});
        try writer.print("  Size of uninitialized data: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfUninitializedData});
        try writer.print("  Address of entry point: 0x{X}\n", .{nt_headers.OptionalHeader.AddressOfEntryPoint});
        try writer.print("  Base of code: 0x{X}\n", .{nt_headers.OptionalHeader.BaseOfCode});
        try writer.print("  Image base: 0x{X}\n", .{nt_headers.OptionalHeader.ImageBase});
        try writer.print("  Section alignment: 0x{X}\n", .{nt_headers.OptionalHeader.SectionAlignment});
        try writer.print("  File alignment: 0x{X}\n", .{nt_headers.OptionalHeader.FileAlignment});
        try writer.print("  Major operating system version: {}\n", .{nt_headers.OptionalHeader.MajorOperatingSystemVersion});
        try writer.print("  Minor operating system version: {}\n", .{nt_headers.OptionalHeader.MinorOperatingSystemVersion});
        try writer.print("  Major image version: {}\n", .{nt_headers.OptionalHeader.MajorImageVersion});
        try writer.print("  Minor image version: {}\n", .{nt_headers.OptionalHeader.MinorImageVersion});
        try writer.print("  Major subsystem version: {}\n", .{nt_headers.OptionalHeader.MajorSubsystemVersion});
        try writer.print("  Minor subsystem version: {}\n", .{nt_headers.OptionalHeader.MinorSubsystemVersion});
        try writer.print("  Win32 version value: 0x{X}\n", .{nt_headers.OptionalHeader.Win32VersionValue});
        try writer.print("  Size of image: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfImage});
        try writer.print("  Size of headers: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfHeaders});
        try writer.print("  CheckSum: 0x{X}\n", .{nt_headers.OptionalHeader.CheckSum});
        try writer.print("  Subsystem: {s} (0x{X})\n", .{ @tagName(nt_headers.OptionalHeader.Subsystem), @intFromEnum(nt_headers.OptionalHeader.Subsystem) });
        try writer.print("  DLL characteristics: 0x{X}\n", .{@as(u16, @bitCast(nt_headers.OptionalHeader.DllCharacteristics))});
        try writer.print("  Size of stack reserve: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfStackReserve});
        try writer.print("  Size of stack commit: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfStackCommit});
        try writer.print("  Size of heap reserve: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfHeapReserve});
        try writer.print("  Size of heap commit: 0x{X}\n", .{nt_headers.OptionalHeader.SizeOfHeapCommit});
        try writer.print("  Loader flags: 0x{X}\n", .{nt_headers.OptionalHeader.LoaderFlags});
        try writer.print("  Number of RVA and sizes: {}\n", .{nt_headers.OptionalHeader.NumberOfRvaAndSizes});

        try writer.writeAll("\nData Directories:\n\n");
        inline for (std.meta.fields(win32.IMAGE_DIRECTORY_ENTRY)) |entry| {
            const data_directory = nt_headers.OptionalHeader.DataDirectory[entry.value];

            try writer.print("\n      * {s} Directory:\n", .{entry.name});
            try writer.print("          RVA: 0x{X}\n", .{data_directory.VirtualAddress});
            try writer.print("          Size: 0x{X}\n", .{data_directory.Size});
        }
    }
};
