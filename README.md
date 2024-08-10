# ZPE - Zig Portable Executable Parser

ZPE is a library and a command-line tool that allows you to parse and inspect the structure of Portable Executable files.

## Features

ZPE can parse and display the following components of a PE file:

- DOS Header
- Rich Header
- NT Headers
- Section Headers
- Import Directory
- Base Relocation Directory

## Usage as a Command-Line Tool

```sh
$ zpe --file-path path/to/your/file
```

You can also selectively display specific parts of the PE file:

```sh
$ zpe --file-path path/to/your/file --print-dos-header --print-nt-headers
```

The Available command-line options are:

- `--file-path`: The path to the Portable Executable file you want to analyze.
- `--print-dos-header`: Print the contents of the DOS header.
- `--print-rich-header`: Print the contents of the Rich header.
- `--print-nt-headers`: Print the contents of the NT headers.
- `--print-section-headers`: Print the contents of the section headers.
- `--print-import-directory`: Print the contents of the import directory.
- `--print-base-relocation-directory`: Print the contents of the base relocation directory.

## Usage as a Library

```zig
const std = @import("std");
const PEParser = @import("zpe").PEParser;

fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var parser = try PEParser.init(allocator, "path/to/your/file");
    defer parser.deinit();

    try parser.parse();

    // Access the parsed information
    std.debug.print("DOS Header Magic: 0x{X}\n", .{parser.dos_header.?.e_magic});
    // ...
}
```

## Contributing

If you find any issues or want to contribute to the development of ZPE, feel free to open a new issue or submit a pull request on the ZPE GitHub repository. 
