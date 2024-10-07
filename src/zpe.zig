const std = @import("std");
pub const types = @import("types.zig");
const datetime = @import("zig-datetime").datetime;
const assert = std.debug.assert;

pub const PEParser = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    reader: std.fs.File.Reader,
    dos_header: ?types.IMAGE_DOS_HEADER = null,
    rich_header_entries: ?[]types.RICH_HEADER_ENTRY = null,
    nt_headers_32: ?types.IMAGE_NT_HEADERS32 = null,
    nt_headers_64: ?types.IMAGE_NT_HEADERS64 = null,
    is_64bit: bool = false,
    section_headers: ?[]types.IMAGE_SECTION_HEADER = null,
    import_directory: ?[]types.IMPORTED_DLL = null,
    export_directory: ?types.EXPORT_DIRECTORY = null,
    base_relocation_directory: ?[]types.BASE_RELOCATION_BLOCK = null,

    // TODO: file path or file content
    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !Self {

        // TODO: keeping the file open until the parser is deinitialized or creating a copy of the file content
        const file = try std.fs.cwd().openFile(file_path, .{});
        const reader = file.reader();

        return .{
            .allocator = allocator,
            .reader = reader,
        };
    }

    pub fn deinit(self: *Self) void {
        self.reader.context.close();
        if (self.rich_header_entries) |rich_header_entries| self.allocator.free(rich_header_entries);
        if (self.section_headers) |section_headers| self.allocator.free(section_headers);

        if (self.import_directory) |import_directory| {
            for (import_directory) |imported_dll| {
                self.allocator.free(imported_dll.Name);
                for (imported_dll.Functions) |function| if (function.Name) |name| self.allocator.free(name);
                self.allocator.free(imported_dll.Functions);
            }
            self.allocator.free(import_directory);
        }

        if (self.export_directory) |export_directory| {
            self.allocator.free(export_directory.Name);
            for (export_directory.Functions) |function| {
                if (function.Anonymous == .Forwarder) self.allocator.free(function.Anonymous.Forwarder);
                self.allocator.free(function.Name);
            }
            self.allocator.free(export_directory.Functions);
        }

        if (self.base_relocation_directory) |base_relocation_directory| {
            for (base_relocation_directory) |base_relocation_block| self.allocator.free(base_relocation_block.Entries);
            self.allocator.free(base_relocation_directory);
        }
    }

    pub fn parse(self: *Self) !void {
        try self.parseDOSHeader();
        try self.parseRichHeader();
        try self.parseNTHeaders();
        try self.parseSectionHeaders();
        try self.parseImportDirectory();
        try self.parseExportDirectory();
        try self.parseBaseRelocationDirectory();
    }

    fn parseDOSHeader(self: *Self) !void {
        try self.reader.context.seekTo(0);

        const IMAGE_DOS_SIGNATURE = 0x5A4D;

        const dos_header = try self.reader.readStruct(types.IMAGE_DOS_HEADER);
        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return error.InvalidDOSHeaderMagic;

        self.dos_header = dos_header;
    }

    fn parseRichHeader(self: *Self) !void {
        assert(self.dos_header != null);

        const dos_header = self.dos_header.?;

        try self.reader.context.seekTo(0);

        var buffer = try self.allocator.alloc(u8, @intCast(dos_header.e_lfanew));
        defer self.allocator.free(buffer);

        try self.reader.readNoEof(buffer);

        const rich_id_index = std.mem.indexOf(u8, buffer, "Rich") orelse return;

        const checksum_text = buffer[rich_id_index + 4 .. rich_id_index + 8];
        const checksum_mask = "DanS";

        var start_marker: [4]u8 = undefined;
        for (0..4) |byte_index| start_marker[byte_index] = checksum_text[byte_index] ^ checksum_mask[byte_index];

        const rich_header_start_index = std.mem.indexOf(u8, buffer, &start_marker) orelse return;

        const rich_header_payload = buffer[rich_header_start_index + 16 .. rich_id_index];

        // TODO: is it required to check the entries length?
        assert(rich_header_payload.len % 8 == 0);

        var rich_header_entries = try self.allocator.alloc(types.RICH_HEADER_ENTRY, rich_header_payload.len / 8);

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
        try self.reader.context.seekTo(@intCast(e_lfanew + @sizeOf(std.os.windows.DWORD) + @sizeOf(types.IMAGE_FILE_HEADER)));

        const optional_header_magic = try self.reader.readEnum(types.IMAGE_OPTIONAL_HEADER_MAGIC, .little);
        self.is_64bit = if (optional_header_magic == .NT_OPTIONAL_HDR_MAGIC) true else false;

        try self.reader.context.seekTo(@intCast(e_lfanew));

        if (self.is_64bit) {
            self.nt_headers_64 = try self.reader.readStruct(types.IMAGE_NT_HEADERS64);
        } else {
            self.nt_headers_32 = try self.reader.readStruct(types.IMAGE_NT_HEADERS32);
        }
    }

    fn parseSectionHeaders(self: *Self) !void {
        assert(self.dos_header != null);
        assert(if (self.is_64bit) self.nt_headers_64 != null else self.nt_headers_32 != null);

        const e_lfanew: usize = @intCast(self.dos_header.?.e_lfanew);

        var file_header: types.IMAGE_FILE_HEADER = undefined;
        var nt_headers_size: usize = 0;

        if (self.is_64bit) {
            file_header = self.nt_headers_64.?.FileHeader;
            nt_headers_size = @sizeOf(types.IMAGE_NT_HEADERS64);
        } else {
            file_header = self.nt_headers_32.?.FileHeader;
            nt_headers_size = @sizeOf(types.IMAGE_NT_HEADERS32);
        }

        var section_headers = try self.allocator.alloc(types.IMAGE_SECTION_HEADER, file_header.NumberOfSections);

        try self.reader.context.seekTo(e_lfanew + nt_headers_size);

        for (0..file_header.NumberOfSections) |section_index| {
            const section_header = try self.reader.readStruct(types.IMAGE_SECTION_HEADER);
            section_headers[section_index] = section_header;
        }

        self.section_headers = section_headers;
    }

    fn parseImportDirectory(self: *Self) !void {
        assert(if (self.is_64bit) self.nt_headers_64 != null else self.nt_headers_32 != null);

        const IMAGE_DIRECTORY_ENTRY_IMPORT = @intFromEnum(types.IMAGE_DIRECTORY_ENTRY.IMPORT);
        const import_directory_va = if (self.is_64bit) self.nt_headers_64.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress else self.nt_headers_32.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        const import_directory_address = try self.rvaToFileOffset(import_directory_va);

        const import_descriptor_size = @sizeOf(types.IMAGE_IMPORT_DESCRIPTOR);
        var import_descriptor_index: usize = 0;

        var import_directory = std.ArrayList(types.IMPORTED_DLL).init(self.allocator);
        errdefer import_directory.deinit();

        while (true) : (import_descriptor_index += 1) {
            try self.reader.context.seekTo(import_directory_address + import_descriptor_size * import_descriptor_index);

            const import_descriptor = try self.reader.readStruct(types.IMAGE_IMPORT_DESCRIPTOR);
            if (import_descriptor.Name == 0 and import_descriptor.FirstThunk == 0) break;

            const name_addr = try self.rvaToFileOffset(import_descriptor.Name);
            try self.reader.context.seekTo(name_addr);

            const name = try self.reader.readUntilDelimiterAlloc(self.allocator, 0, std.math.maxInt(u32));

            const ilt_addr = try self.rvaToFileOffset(import_descriptor.Anonymous.OriginalFirstThunk);

            const entry_size: usize = if (self.is_64bit) @sizeOf(types.ILT_ENTRY64) else @sizeOf(types.ILT_ENTRY32);
            var entry_index: usize = 0;

            var functions = std.ArrayList(types.IMPORTED_FUNCTION).init(self.allocator);
            errdefer functions.deinit();

            while (true) : (entry_index += 1) {
                try self.reader.context.seekTo(ilt_addr + entry_size * entry_index);

                var flag: u1 = 0;
                var ordinal: u16 = 0;
                var hint_rva: u31 = 0;

                if (self.is_64bit) {
                    const entry = try self.reader.readStruct(types.ILT_ENTRY64);
                    flag = entry.ORDINAL_NAME_FLAG;
                    ordinal = entry.ANONYMOUS.ORDINAL;
                    hint_rva = entry.ANONYMOUS.HINT_NAME_TABLE_RVA;
                } else {
                    const entry = try self.reader.readStruct(types.ILT_ENTRY32);
                    flag = entry.ORDINAL_NAME_FLAG;
                    ordinal = entry.ANONYMOUS.ORDINAL;
                    hint_rva = entry.ANONYMOUS.HINT_NAME_TABLE_RVA;
                }

                if (flag == 0 and hint_rva == 0 and ordinal == 0) break;

                var imported_function = types.IMPORTED_FUNCTION{
                    .Name = null,
                    .Hint = null,
                    .Ordinal = null,
                };

                if (flag == 0) {
                    const hint_addr = try self.rvaToFileOffset(hint_rva);
                    try self.reader.context.seekTo(hint_addr);

                    const hint = try self.reader.readInt(u16, .little);
                    const entry_name = try self.reader.readUntilDelimiterAlloc(self.allocator, 0, std.math.maxInt(u32));

                    imported_function.Hint = hint;
                    imported_function.Name = entry_name;
                } else {
                    imported_function.Ordinal = ordinal;
                }

                try functions.append(imported_function);
            }

            try import_directory.append(.{
                .Name = name,
                .OriginalFirstThunk = import_descriptor.Anonymous.OriginalFirstThunk,
                .TimeDateStamp = import_descriptor.TimeDateStamp,
                .ForwarderChain = import_descriptor.ForwarderChain,
                .NameRva = import_descriptor.Name,
                .FirstThunk = import_descriptor.FirstThunk,
                .Functions = try functions.toOwnedSlice(),
            });
        }

        self.import_directory = try import_directory.toOwnedSlice();
    }

    fn parseExportDirectory(self: *Self) !void {
        assert(if (self.is_64bit) self.nt_headers_64 != null else self.nt_headers_32 != null);

        const IMAGE_DIRECTORY_ENTRY_EXPORT = @intFromEnum(types.IMAGE_DIRECTORY_ENTRY.EXPORT);
        const export_directory_va = if (self.is_64bit) self.nt_headers_64.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress else self.nt_headers_32.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        const export_directory_size = if (self.is_64bit) self.nt_headers_64.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size else self.nt_headers_32.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (export_directory_va == 0) return;

        const export_directory_address = try self.rvaToFileOffset(export_directory_va);

        try self.reader.context.seekTo(export_directory_address);

        const export_directory = try self.reader.readStruct(types.IMAGE_EXPORT_DIRECTORY);

        const dll_name_address = try self.rvaToFileOffset(export_directory.Name);
        try self.reader.context.seekTo(dll_name_address);
        const dll_name = try self.reader.readUntilDelimiterAlloc(self.allocator, 0, std.math.maxInt(u32));

        const num_of_functions = export_directory.NumberOfFunctions;

        const export_address_table_address = try self.rvaToFileOffset(export_directory.AddressOfFunctions);
        const export_address_table = try self.allocator.alloc(types.EXPORT_ADDRESS_TABLE_ENTRY, num_of_functions);
        defer self.allocator.free(export_address_table);
        for (0..num_of_functions) |i| {
            try self.reader.context.seekTo(export_address_table_address + i * 4);

            const rva = try self.reader.readInt(u32, .little);
            if (rva >= export_directory_va and rva < export_directory_va + export_directory_size) {
                const address = try self.rvaToFileOffset(rva);
                try self.reader.context.seekTo(address);
                const forwarder = try self.reader.readUntilDelimiterAlloc(self.allocator, 0, std.math.maxInt(u32));
                export_address_table[i] = .{ .Forwarder = forwarder };
            } else {
                export_address_table[i] = .{ .ExportRva = rva };
            }
        }

        const export_name_pointer_table_address = try self.rvaToFileOffset(export_directory.AddressOfNames);
        const export_name_pointer_table = try self.allocator.alloc(struct { Name: []const u8, Rva: u32 }, num_of_functions);
        defer self.allocator.free(export_name_pointer_table);
        for (0..num_of_functions) |i| {
            try self.reader.context.seekTo(export_name_pointer_table_address + i * 4);

            const name_rva = try self.reader.readInt(u32, .little);
            const name_address = try self.rvaToFileOffset(name_rva);
            try self.reader.context.seekTo(name_address);
            const name = try self.reader.readUntilDelimiterAlloc(self.allocator, 0, std.math.maxInt(u32));
            export_name_pointer_table[i] = .{ .Name = name, .Rva = name_rva };
        }

        const export_ordinal_table_address = try self.rvaToFileOffset(export_directory.AddressOfNameOrdinals);
        const export_ordinal_table = try self.allocator.alloc(u16, num_of_functions);
        defer self.allocator.free(export_ordinal_table);
        try self.reader.context.seekTo(export_ordinal_table_address);
        for (0..num_of_functions) |i| {
            const ordinal = try self.reader.readInt(u16, .little);
            export_ordinal_table[i] = ordinal + @as(u16, @intCast(export_directory.Base));
        }

        const exported_functions = try self.allocator.alloc(types.EXPORTED_FUNCTION, num_of_functions);
        for (0..num_of_functions) |i| {
            exported_functions[i] = .{
                .Anonymous = export_address_table[i],
                .NameRva = export_name_pointer_table[i].Rva,
                .Name = export_name_pointer_table[i].Name,
                .Ordinal = export_ordinal_table[i],
            };
        }

        self.export_directory = .{
            .Characteristics = export_directory.Characteristics,
            .TimeDateStamp = export_directory.TimeDateStamp,
            .MajorVersion = export_directory.MajorVersion,
            .MinorVersion = export_directory.MinorVersion,
            .NameRva = export_directory.Name,
            .Name = dll_name,
            .Base = export_directory.Base,
            .NumberOfFunctions = export_directory.NumberOfFunctions,
            .NumberOfNames = export_directory.NumberOfNames,
            .AddressOfFunctions = export_directory.AddressOfFunctions,
            .AddressOfNames = export_directory.AddressOfNames,
            .AddressOfNameOrdinals = export_directory.AddressOfNameOrdinals,
            .Functions = exported_functions,
        };
    }

    fn parseBaseRelocationDirectory(self: *Self) !void {
        assert(if (self.is_64bit) self.nt_headers_64 != null else self.nt_headers_32 != null);

        const IMAGE_DIRECTORY_ENTRY_BASERELOC = @intFromEnum(types.IMAGE_DIRECTORY_ENTRY.BASERELOC);
        const basereloc_directory_va = if (self.is_64bit) self.nt_headers_64.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress else self.nt_headers_32.?.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        const basereloc_directory_address = try self.rvaToFileOffset(basereloc_directory_va);

        try self.reader.context.seekTo(basereloc_directory_address);

        var base_relocation_directory = std.ArrayList(types.BASE_RELOCATION_BLOCK).init(self.allocator);
        errdefer base_relocation_directory.deinit();

        while (true) {
            const base_relocation = try self.reader.readStruct(types.IMAGE_BASE_RELOCATION);

            if (base_relocation.VirtualAddress == 0 and base_relocation.SizeOfBlock == 0) break;

            const entries_len = (base_relocation.SizeOfBlock - @sizeOf(types.IMAGE_BASE_RELOCATION)) / @sizeOf(types.BASE_RELOCATION_ENTRY);

            var entries = std.ArrayList(types.BASE_RELOCATION_ENTRY).init(self.allocator);
            errdefer entries.deinit();

            for (0..entries_len) |_| {
                const entry = try self.reader.readStruct(types.BASE_RELOCATION_ENTRY);
                try entries.append(entry);
            }

            try base_relocation_directory.append(.{
                .VirtualAddress = base_relocation.VirtualAddress,
                .SizeOfBlock = base_relocation.SizeOfBlock,
                .Entries = try entries.toOwnedSlice(),
            });
        }

        self.base_relocation_directory = try base_relocation_directory.toOwnedSlice();
    }

    pub fn rvaToFileOffset(self: Self, rva: u32) !u32 {
        const section_headers = self.section_headers orelse return error.SectionHeadersNotParsed;

        for (section_headers) |section| {
            if (rva >= section.VirtualAddress and rva < section.VirtualAddress + section.Misc.VirtualSize) {
                return (rva - section.VirtualAddress) + section.PointerToRawData;
            }
        }

        return error.RVANotFound;
    }

    pub fn print(self: Self, writer: anytype) !void {
        try self.printDOSHeaderInfo(writer);
        try writer.writeAll("\n");
        try self.printRichHeaderInfo(writer);
        try writer.writeAll("\n");
        try self.printNTHeadersInfo(writer);
        try writer.writeAll("\n");
        try self.printSectionHeadersInfo(writer);
        try writer.writeAll("\n");
        try self.printImportDirectoryInfo(writer);
        try writer.writeAll("\n");
        try self.printExportDirectoryInfo(writer);
        try writer.writeAll("\n");
        try self.printBaseRelocationDirectoryInfo(writer);
        try writer.writeAll("\n");
    }

    pub fn printDOSHeaderInfo(self: Self, writer: anytype) !void {
        const dos_header = self.dos_header orelse return;

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

    pub fn printRichHeaderInfo(self: Self, writer: anytype) !void {
        const rich_header_entries = self.rich_header_entries orelse return;

        try writer.writeAll("Rich Header:\n");
        try writer.writeAll("------------\n\n");

        for (rich_header_entries) |entry| {
            try writer.print(" 0x{X:0>4} 0x{X:0>4} 0x{X:0>8}: {d}.{d}.{d}\n", .{ entry.build_id, entry.product_id, entry.use_count, entry.build_id, entry.product_id, entry.use_count });
        }
    }

    pub fn printNTHeadersInfo(self: Self, writer: anytype) !void {
        try writer.writeAll("NT Headers:\n");
        try writer.writeAll("------------\n\n");

        if (self.is_64bit) {
            try self.printNTHeaders64Info(writer);
        } else {
            try self.printNTHeaders32Info(writer);
        }
    }

    pub fn printNTHeaders32Info(self: Self, writer: anytype) !void {
        const nt_headers = self.nt_headers_32 orelse return;

        try writer.print("  PE Signature: 0x{X}\n", .{nt_headers.Signature});

        try printNTFileHeaderInfo(writer, nt_headers.FileHeader);
        try printNTOptionalHeaderFields(writer, nt_headers.OptionalHeader);
    }

    pub fn printNTHeaders64Info(self: Self, writer: anytype) !void {
        const nt_headers = self.nt_headers_64 orelse return;

        try writer.print("  PE Signature: 0x{X}\n", .{nt_headers.Signature});

        try printNTFileHeaderInfo(writer, nt_headers.FileHeader);
        try printNTOptionalHeaderFields(writer, nt_headers.OptionalHeader);
    }

    pub fn printNTFileHeaderInfo(writer: anytype, file_header: types.IMAGE_FILE_HEADER) !void {
        try writer.writeAll("\nFile Header:\n\n");
        try writer.print("  Machine: {s} (0x{X})\n", .{ @tagName(file_header.Machine), @intFromEnum(file_header.Machine) });
        try writer.print("  Number of sections: {}\n", .{file_header.NumberOfSections});

        var buf: [60]u8 = undefined;
        const time_date_string = try datetime.Datetime.fromSeconds(@floatFromInt(file_header.TimeDateStamp)).formatHttpBuf(&buf);
        try writer.print("  TimeDateStamp: 0x{X} ({s})\n", .{ file_header.TimeDateStamp, time_date_string });

        try writer.print("  Pointer to symbol table: 0x{X}\n", .{file_header.PointerToSymbolTable});
        try writer.print("  Number of symbols: {}\n", .{file_header.NumberOfSymbols});
        try writer.print("  Size of optional header: {}\n", .{file_header.SizeOfOptionalHeader});

        try writer.print("  Characteristics: 0x{X}\n", .{@as(u16, @bitCast(file_header.Characteristics))});
        inline for (std.meta.fields(types.IMAGE_FILE_CHARACTERISTICS)) |field| {
            const value = @field(file_header.Characteristics, field.name);
            if (field.name[0] != '_' and value == 1) {
                try writer.print("      {s}\n", .{field.name});
            }
        }
    }

    pub fn printNTOptionalHeaderFields(writer: anytype, optional_header: anytype) !void {
        try writer.writeAll("\nOptional Header:\n\n");
        try writer.print("  Magic: 0x{X}\n", .{@intFromEnum(optional_header.Magic)});
        try writer.print("  Major linker version: 0x{X}\n", .{optional_header.MajorLinkerVersion});
        try writer.print("  Minor linker version: 0x{X}\n", .{optional_header.MinorLinkerVersion});
        try writer.print("  Size of code: 0x{X}\n", .{optional_header.SizeOfCode});
        try writer.print("  Size of initialized data: 0x{X}\n", .{optional_header.SizeOfInitializedData});
        try writer.print("  Size of uninitialized data: 0x{X}\n", .{optional_header.SizeOfUninitializedData});
        try writer.print("  Address of entry point: 0x{X}\n", .{optional_header.AddressOfEntryPoint});
        try writer.print("  Base of code: 0x{X}\n", .{optional_header.BaseOfCode});
        if (@hasField(@TypeOf(optional_header), "BaseOfData")) {
            try writer.print("  Base of data: 0x{X}\n", .{optional_header.BaseOfData});
        }
        try writer.print("  Image base: 0x{X}\n", .{optional_header.ImageBase});
        try writer.print("  Section alignment: 0x{X}\n", .{optional_header.SectionAlignment});
        try writer.print("  File alignment: 0x{X}\n", .{optional_header.FileAlignment});
        try writer.print("  Major operating system version: 0x{X}\n", .{optional_header.MajorOperatingSystemVersion});
        try writer.print("  Minor operating system version: 0x{X}\n", .{optional_header.MinorOperatingSystemVersion});
        try writer.print("  Major image version: 0x{X}\n", .{optional_header.MajorImageVersion});
        try writer.print("  Minor image version: 0x{X}\n", .{optional_header.MinorImageVersion});
        try writer.print("  Major subsystem version: 0x{X}\n", .{optional_header.MajorSubsystemVersion});
        try writer.print("  Minor subsystem version: 0x{X}\n", .{optional_header.MinorSubsystemVersion});
        try writer.print("  Win32 version value: 0x{X}\n", .{optional_header.Win32VersionValue});
        try writer.print("  Size of image: 0x{X}\n", .{optional_header.SizeOfImage});
        try writer.print("  Size of headers: 0x{X}\n", .{optional_header.SizeOfHeaders});
        try writer.print("  CheckSum: 0x{X}\n", .{optional_header.CheckSum});
        try writer.print("  Subsystem: 0x{X} ({s})\n", .{ @intFromEnum(optional_header.Subsystem), @tagName(optional_header.Subsystem) });

        try writer.print("  DLL characteristics: 0x{X}\n", .{@as(u16, @bitCast(optional_header.DllCharacteristics))});
        inline for (std.meta.fields(types.IMAGE_DLL_CHARACTERISTICS)) |field| {
            const value = @field(optional_header.DllCharacteristics, field.name);
            if (field.name[0] != '_' and value == 1) {
                try writer.print("      {s}\n", .{field.name});
            }
        }

        try writer.print("  Size of stack reserve: 0x{X}\n", .{optional_header.SizeOfStackReserve});
        try writer.print("  Size of stack commit: 0x{X}\n", .{optional_header.SizeOfStackCommit});
        try writer.print("  Size of heap reserve: 0x{X}\n", .{optional_header.SizeOfHeapReserve});
        try writer.print("  Size of heap commit: 0x{X}\n", .{optional_header.SizeOfHeapCommit});
        try writer.print("  Loader flags: 0x{X}\n", .{optional_header.LoaderFlags});
        try writer.print("  Number of RVA and sizes: {}\n", .{optional_header.NumberOfRvaAndSizes});

        try writer.writeAll("\nData Directories:\n\n");
        inline for (std.meta.fields(types.IMAGE_DIRECTORY_ENTRY)) |entry| {
            const data_directory = optional_header.DataDirectory[entry.value];

            try writer.print("\n      * {s} Directory:\n", .{entry.name});
            try writer.print("          RVA: 0x{X}\n", .{data_directory.VirtualAddress});
            try writer.print("          Size: 0x{X}\n", .{data_directory.Size});
        }
    }

    pub fn printSectionHeadersInfo(self: Self, writer: anytype) !void {
        const section_headers = self.section_headers orelse return;

        try writer.writeAll("Section Headers:\n");
        try writer.writeAll("----------------\n\n");

        for (section_headers) |section| {
            try writer.print("  * {s}\n", .{section.Name});
            try writer.print("      Virtual Size: 0x{X}\n", .{section.Misc.VirtualSize});
            try writer.print("      Virtual Address: 0x{X}\n", .{section.VirtualAddress});
            try writer.print("      Size of Raw Data: 0x{X}\n", .{section.SizeOfRawData});
            try writer.print("      Pointer to Raw Data: 0x{X}\n", .{section.PointerToRawData});
            try writer.print("      Pointer to Relocations: 0x{X}\n", .{section.PointerToRelocations});
            try writer.print("      Pointer to Line Numbers: 0x{X}\n", .{section.PointerToLinenumbers});
            try writer.print("      Number of Relocations: {d}\n", .{section.NumberOfRelocations});
            try writer.print("      Number of Line Numbers: {d}\n", .{section.NumberOfLinenumbers});

            try writer.print("      Characteristics: 0x{X}\n", .{@as(u32, @bitCast(section.Characteristics))});
            inline for (std.meta.fields(types.IMAGE_SECTION_CHARACTERISTICS)) |field| {
                const value = @field(section.Characteristics, field.name);
                if (field.name[0] != '_' and value == 1) {
                    try writer.print("          {s}\n", .{field.name});
                }
            }

            try writer.writeAll("\n");
        }
    }

    pub fn printImportDirectoryInfo(self: Self, writer: anytype) !void {
        const import_directory = self.import_directory orelse return;

        try writer.writeAll("IMPORT TABLE:\n");
        try writer.writeAll("--------------\n\n");

        for (import_directory) |imported_dll| {
            try writer.print("  * {s}:\n", .{imported_dll.Name});

            try writer.print("      ILT RVA: 0x{X}\n", .{imported_dll.OriginalFirstThunk});
            try writer.print("      IAT RVA: 0x{X}\n", .{imported_dll.FirstThunk});
            try writer.print("      Name RVA: 0x{X}\n", .{imported_dll.NameRva});

            var buf: [60]u8 = undefined;
            const time_date_string = try datetime.Datetime.fromSeconds(@floatFromInt(imported_dll.TimeDateStamp)).formatHttpBuf(&buf);
            try writer.print("      TimeDateStamp: 0x{X} ({s})\n", .{ imported_dll.TimeDateStamp, time_date_string });

            try writer.print("      ForwarderChain: 0x{x}\n", .{imported_dll.ForwarderChain});
            try writer.print("      Bound: {}\n", .{imported_dll.TimeDateStamp != 0});
            try writer.print("      Function Count: {}\n", .{imported_dll.Functions.len});

            for (imported_dll.Functions) |function| {
                try writer.writeAll("\n     Entry:\n");

                if (function.Name) |entry_name| try writer.print("          Name: {s}\n", .{entry_name});
                if (function.Hint) |hint| try writer.print("          Hint: 0x{X}\n", .{hint});
                if (function.Ordinal) |ordinal| try writer.print("          Ordinal: 0x{X}\n", .{ordinal});
            }

            try writer.writeAll("\n   ----------------------\n\n");
        }
    }

    pub fn printExportDirectoryInfo(self: Self, writer: anytype) !void {
        const export_directory = self.export_directory orelse return;

        try writer.writeAll("EXPORT TABLE:\n");
        try writer.writeAll("--------------\n\n");

        try writer.print("  Characteristics: 0x{X}\n", .{export_directory.Characteristics});

        var buf: [60]u8 = undefined;
        const time_date_string = try datetime.Datetime.fromSeconds(@floatFromInt(export_directory.TimeDateStamp)).formatHttpBuf(&buf);
        try writer.print("  TimeDateStamp: 0x{X} ({s})\n", .{ export_directory.TimeDateStamp, time_date_string });

        try writer.print("  MajorVersion: 0x{X}\n", .{export_directory.MajorVersion});
        try writer.print("  MinorVersion: 0x{X}\n", .{export_directory.MinorVersion});
        try writer.print("  Name RVA: 0x{X}\n", .{export_directory.NameRva});
        try writer.print("  Name: {s}\n", .{export_directory.Name});
        try writer.print("  Base: 0x{X}\n", .{export_directory.Base});
        try writer.print("  Number Of Functions: 0x{X}\n", .{export_directory.NumberOfFunctions});
        try writer.print("  Number Of Names: 0x{X}\n", .{export_directory.NumberOfNames});
        try writer.print("  Functions RVA: 0x{X}\n", .{export_directory.AddressOfFunctions});
        try writer.print("  Names RVA: 0x{X}\n", .{export_directory.AddressOfNames});
        try writer.print("  NameOrdinals RVA: 0x{X}\n", .{export_directory.AddressOfNameOrdinals});

        try writer.writeAll("  Exported Functions:\n\n");
        for (export_directory.Functions) |function| {
            try writer.print("      Ordinal: 0x{X}\n", .{function.Ordinal});
            switch (function.Anonymous) {
                .Forwarder => |forwarder| try writer.print("      Forwarder: {s}\n", .{forwarder}),
                .ExportRva => |rva| try writer.print("      Function RVA: 0x{X}\n", .{rva}),
            }
            try writer.print("      Name RVA: 0x{X}\n", .{function.NameRva});
            try writer.print("      Name: {s}\n\n", .{function.Name});
        }
    }

    pub fn printBaseRelocationDirectoryInfo(self: Self, writer: anytype) !void {
        const base_relocation_directory = self.base_relocation_directory orelse return;

        try writer.writeAll("BASE RELOCATION TABLE:\n");
        try writer.writeAll("----------------------\n\n");

        for (base_relocation_directory, 0..) |base_relocation_block, i| {
            try writer.print("\n    Block: 0x{X}: \n", .{i});
            try writer.print("      Page RVA: 0x{X}\n", .{base_relocation_block.VirtualAddress});
            try writer.print("      Block size: 0x{X}\n", .{base_relocation_block.SizeOfBlock});
            try writer.print("      Number of entries: 0x{X}\n", .{base_relocation_block.Entries.len});
            try writer.writeAll("\n    Entries:\n");

            for (base_relocation_block.Entries) |entry| {
                try writer.print("\n        * Value: 0x{X}\n", .{@as(u16, @bitCast(entry))});
                try writer.print("          Relocation Type: 0x{X}\n", .{entry.TYPE});
                try writer.print("          Offset: 0x{X}\n", .{entry.OFFSET});
            }

            try writer.writeAll("\n   ----------------------\n\n");
        }
    }
};
