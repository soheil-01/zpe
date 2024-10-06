const std = @import("std");
const cli = @import("zig-cli");
const PEParser = @import("zpe").PEParser;

var config = struct {
    file_path: []const u8 = undefined,
    print_dos_header: bool = false,
    print_rich_header: bool = false,
    print_nt_headers: bool = false,
    print_section_headers: bool = false,
    print_import_directory: bool = false,
    print_export_directory: bool = false,
    print_base_relocation_directory: bool = false,
}{};

pub fn main() !void {
    var r = try cli.AppRunner.init(std.heap.page_allocator);

    const app = cli.App{
        .command = cli.Command{
            .name = "parse",
            .description = .{ .one_line = "Portable Executable parser" },
            .options = &.{
                .{
                    .long_name = "file-path",
                    .help = "Path to the PE file",
                    .required = true,
                    .value_ref = r.mkRef(&config.file_path),
                },
                .{
                    .long_name = "print-dos-header",
                    .help = "Print DOS header information",
                    .value_ref = r.mkRef(&config.print_dos_header),
                },
                .{
                    .long_name = "print-rich-header",
                    .help = "Print Rich header information",
                    .value_ref = r.mkRef(&config.print_rich_header),
                },
                .{
                    .long_name = "print-nt-headers",
                    .help = "Print NT headers information",
                    .value_ref = r.mkRef(&config.print_nt_headers),
                },
                .{
                    .long_name = "print-section-headers",
                    .help = "Print section headers information",
                    .value_ref = r.mkRef(&config.print_section_headers),
                },
                .{
                    .long_name = "print-import-directory",
                    .help = "Print import directory information",
                    .value_ref = r.mkRef(&config.print_import_directory),
                },
                .{
                    .long_name = "print-export-directory",
                    .help = "Print export directory information",
                    .value_ref = r.mkRef(&config.print_export_directory),
                },
                .{
                    .long_name = "print-base-relocation-directory",
                    .help = "Print base relocation directory information",
                    .value_ref = r.mkRef(&config.print_base_relocation_directory),
                },
            },
            .target = cli.CommandTarget{
                .action = cli.CommandAction{
                    .exec = run_parser,
                },
            },
        },
    };

    return r.run(&app);
}

fn run_parser() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var parser = try PEParser.init(allocator, config.file_path);
    defer parser.deinit();

    try parser.parse();

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());

    const stdout = bw.writer();

    if (!config.print_dos_header and !config.print_rich_header and !config.print_nt_headers and !config.print_section_headers and !config.print_import_directory and !config.print_base_relocation_directory and !config.print_export_directory) {
        try parser.print(stdout);
    } else {
        if (config.print_dos_header) {
            try parser.printDOSHeaderInfo(stdout);
        }
        if (config.print_rich_header) {
            try parser.printRichHeaderInfo(stdout);
        }
        if (config.print_nt_headers) {
            try parser.printNTHeadersInfo(stdout);
        }
        if (config.print_section_headers) {
            try parser.printSectionHeadersInfo(stdout);
        }
        if (config.print_import_directory) {
            try parser.printImportDirectoryInfo(stdout);
        }
        if (config.print_export_directory) {
            try parser.printExportDirectoryInfo(stdout);
        }
        if (config.print_base_relocation_directory) {
            try parser.printBaseRelocationDirectoryInfo(stdout);
        }
    }

    try bw.flush();
}
