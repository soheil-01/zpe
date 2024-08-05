pub const RICH_HEADER_ENTRY = struct {
    build_id: u16,
    product_id: u16,
    use_count: u32,
};

// Note: These types are copied from the zigwin32 library (https://github.com/marlersoft/zigwin32)
// due to alignment issues in the original library and to improve ZLS performance by avoiding
// the inclusion of the entire library. Modifications have been made to correct alignment problems.

pub const IMAGE_DOS_SIGNATURE = @as(u16, 23117);

pub const IMAGE_DIRECTORY_ENTRY = enum(u32) {
    ARCHITECTURE = 7,
    BASERELOC = 5,
    BOUND_IMPORT = 11,
    COM_DESCRIPTOR = 14,
    DEBUG = 6,
    DELAY_IMPORT = 13,
    EXCEPTION = 3,
    EXPORT = 0,
    GLOBALPTR = 8,
    IAT = 12,
    IMPORT = 1,
    LOAD_CONFIG = 10,
    RESOURCE = 2,
    SECURITY = 4,
    TLS = 9,
};

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16 align(2),
    e_cblp: u16 align(2),
    e_cp: u16 align(2),
    e_crlc: u16 align(2),
    e_cparhdr: u16 align(2),
    e_minalloc: u16 align(2),
    e_maxalloc: u16 align(2),
    e_ss: u16 align(2),
    e_sp: u16 align(2),
    e_csum: u16 align(2),
    e_ip: u16 align(2),
    e_cs: u16 align(2),
    e_lfarlc: u16 align(2),
    e_ovno: u16 align(2),
    e_res: [4]u16 align(2),
    e_oemid: u16 align(2),
    e_oeminfo: u16 align(2),
    e_res2: [10]u16 align(2),
    e_lfanew: i32 align(2),
};

pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_NT_HEADERS32 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

pub const IMAGE_FILE_MACHINE = enum(u16) {
    AXP64 = 644,
    I386 = 332,
    IA64 = 512,
    AMD64 = 34404,
    UNKNOWN = 0,
    TARGET_HOST = 1,
    R3000 = 354,
    R4000 = 358,
    R10000 = 360,
    WCEMIPSV2 = 361,
    ALPHA = 388,
    SH3 = 418,
    SH3DSP = 419,
    SH3E = 420,
    SH4 = 422,
    SH5 = 424,
    ARM = 448,
    THUMB = 450,
    ARMNT = 452,
    AM33 = 467,
    POWERPC = 496,
    POWERPCFP = 497,
    MIPS16 = 614,
    // ALPHA64 = 644, this enum value conflicts with AXP64
    MIPSFPU = 870,
    MIPSFPU16 = 1126,
    TRICORE = 1312,
    CEF = 3311,
    EBC = 3772,
    M32R = 36929,
    ARM64 = 43620,
    CEE = 49390,
};

pub const IMAGE_FILE_CHARACTERISTICS = packed struct(u16) {
    RELOCS_STRIPPED: u1 = 0,
    EXECUTABLE_IMAGE: u1 = 0,
    LINE_NUMS_STRIPPED: u1 = 0,
    LOCAL_SYMS_STRIPPED: u1 = 0,
    AGGRESIVE_WS_TRIM: u1 = 0,
    LARGE_ADDRESS_AWARE: u1 = 0,
    _6: u1 = 0,
    BYTES_REVERSED_LO: u1 = 0,
    @"32BIT_MACHINE": u1 = 0,
    DEBUG_STRIPPED: u1 = 0,
    REMOVABLE_RUN_FROM_SWAP: u1 = 0,
    NET_RUN_FROM_SWAP: u1 = 0,
    SYSTEM: u1 = 0,
    DLL: u1 = 0,
    UP_SYSTEM_ONLY: u1 = 0,
    BYTES_REVERSED_HI: u1 = 0,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: IMAGE_FILE_MACHINE,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: IMAGE_FILE_CHARACTERISTICS,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_OPTIONAL_HEADER_MAGIC = enum(u16) {
    NT_OPTIONAL_HDR_MAGIC = 523,
    NT_OPTIONAL_HDR32_MAGIC = 267,
    // NT_OPTIONAL_HDR64_MAGIC = 523, this enum value conflicts with NT_OPTIONAL_HDR_MAGIC
    ROM_OPTIONAL_HDR_MAGIC = 263,
};

pub const IMAGE_SUBSYSTEM = enum(u16) {
    UNKNOWN = 0,
    NATIVE = 1,
    WINDOWS_GUI = 2,
    WINDOWS_CUI = 3,
    OS2_CUI = 5,
    POSIX_CUI = 7,
    NATIVE_WINDOWS = 8,
    WINDOWS_CE_GUI = 9,
    EFI_APPLICATION = 10,
    EFI_BOOT_SERVICE_DRIVER = 11,
    EFI_RUNTIME_DRIVER = 12,
    EFI_ROM = 13,
    XBOX = 14,
    WINDOWS_BOOT_APPLICATION = 16,
    XBOX_CODE_CATALOG = 17,
};

pub const IMAGE_DLL_CHARACTERISTICS = packed struct(u16) {
    EX_CET_COMPAT: u1 = 0,
    EX_CET_COMPAT_STRICT_MODE: u1 = 0,
    EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE: u1 = 0,
    EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC: u1 = 0,
    EX_CET_RESERVED_1: u1 = 0,
    HIGH_ENTROPY_VA: u1 = 0,
    DYNAMIC_BASE: u1 = 0,
    FORCE_INTEGRITY: u1 = 0,
    NX_COMPAT: u1 = 0,
    NO_ISOLATION: u1 = 0,
    NO_SEH: u1 = 0,
    NO_BIND: u1 = 0,
    APPCONTAINER: u1 = 0,
    WDM_DRIVER: u1 = 0,
    GUARD_CF: u1 = 0,
    TERMINAL_SERVER_AWARE: u1 = 0,
    // EX_CET_RESERVED_2 (bit index 5) conflicts with HIGH_ENTROPY_VA
};

pub const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: IMAGE_SUBSYSTEM,
    DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    /// Deprecated
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: IMAGE_SUBSYSTEM,
    DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    /// Deprecated
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_SECTION_CHARACTERISTICS = packed struct(u32) {
    SCALE_INDEX: u1 = 0,
    _1: u1 = 0,
    _2: u1 = 0,
    TYPE_NO_PAD: u1 = 0,
    _4: u1 = 0,
    CNT_CODE: u1 = 0,
    CNT_INITIALIZED_DATA: u1 = 0,
    CNT_UNINITIALIZED_DATA: u1 = 0,
    LNK_OTHER: u1 = 0,
    LNK_INFO: u1 = 0,
    _10: u1 = 0,
    LNK_REMOVE: u1 = 0,
    LNK_COMDAT: u1 = 0,
    _13: u1 = 0,
    NO_DEFER_SPEC_EXC: u1 = 0,
    GPREL: u1 = 0,
    _16: u1 = 0,
    MEM_PURGEABLE: u1 = 0,
    MEM_LOCKED: u1 = 0,
    MEM_PRELOAD: u1 = 0,
    ALIGN_1BYTES: u1 = 0,
    ALIGN_2BYTES: u1 = 0,
    ALIGN_8BYTES: u1 = 0,
    ALIGN_128BYTES: u1 = 0,
    LNK_NRELOC_OVFL: u1 = 0,
    MEM_DISCARDABLE: u1 = 0,
    MEM_NOT_CACHED: u1 = 0,
    MEM_NOT_PAGED: u1 = 0,
    MEM_SHARED: u1 = 0,
    MEM_EXECUTE: u1 = 0,
    MEM_READ: u1 = 0,
    MEM_WRITE: u1 = 0,
    // MEM_FARDATA (bit index 15) conflicts with GPREL
    // MEM_16BIT (bit index 17) conflicts with MEM_PURGEABLE
};

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    Misc: extern union {
        PhysicalAddress: u32,
        VirtualSize: u32,
    },
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: IMAGE_SECTION_CHARACTERISTICS,
};

pub const IMAGE_IMPORT_DESCRIPTOR = extern struct {
    Anonymous: extern union {
        Characteristics: u32,
        OriginalFirstThunk: u32,
    },
    TimeDateStamp: u32,
    ForwarderChain: u32,
    Name: u32,
    FirstThunk: u32,
};

pub const ILT_ENTRY32 = packed struct(u32) {
    Anonymous: packed union {
        Ordinal: u16,
        HintNameTableRVA: u31,
    },
    OrdinalNameFlag: u1,
};

pub const ILT_ENTRY64 = packed struct(u64) {
    Anonymous: packed union {
        Ordinal: u16,
        HintNameTableRVA: u31,
    },
    _1: u32,
    OrdinalNameFlag: u1,
};
