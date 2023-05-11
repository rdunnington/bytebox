const std = @import("std");

// A compressed version of the wasm opcodes for better table-oriented lookup (no holes). See WasmOpcode for the actual wasm representation.
pub const Opcode = enum(u16) {
    Invalid, // Has no corresponding mapping in WasmOpcode.
    Unreachable,
    Noop,
    Block,
    Loop,
    If,
    IfNoElse, // variant of If that assumes no else branch
    Else,
    End,
    Branch,
    Branch_If,
    Branch_Table,
    Return,
    Call,
    Call_Indirect,
    Drop,
    Select,
    Select_T,
    Local_Get,
    Local_Set,
    Local_Tee,
    Global_Get,
    Global_Set,
    Table_Get,
    Table_Set,
    I32_Load,
    I64_Load,
    F32_Load,
    F64_Load,
    I32_Load8_S,
    I32_Load8_U,
    I32_Load16_S,
    I32_Load16_U,
    I64_Load8_S,
    I64_Load8_U,
    I64_Load16_S,
    I64_Load16_U,
    I64_Load32_S,
    I64_Load32_U,
    I32_Store,
    I64_Store,
    F32_Store,
    F64_Store,
    I32_Store8,
    I32_Store16,
    I64_Store8,
    I64_Store16,
    I64_Store32,
    Memory_Size,
    Memory_Grow,
    I32_Const,
    I64_Const,
    F32_Const,
    F64_Const,
    I32_Eqz,
    I32_Eq,
    I32_NE,
    I32_LT_S,
    I32_LT_U,
    I32_GT_S,
    I32_GT_U,
    I32_LE_S,
    I32_LE_U,
    I32_GE_S,
    I32_GE_U,
    I64_Eqz,
    I64_Eq,
    I64_NE,
    I64_LT_S,
    I64_LT_U,
    I64_GT_S,
    I64_GT_U,
    I64_LE_S,
    I64_LE_U,
    I64_GE_S,
    I64_GE_U,
    F32_EQ,
    F32_NE,
    F32_LT,
    F32_GT,
    F32_LE,
    F32_GE,
    F64_EQ,
    F64_NE,
    F64_LT,
    F64_GT,
    F64_LE,
    F64_GE,
    I32_Clz,
    I32_Ctz,
    I32_Popcnt,
    I32_Add,
    I32_Sub,
    I32_Mul,
    I32_Div_S,
    I32_Div_U,
    I32_Rem_S,
    I32_Rem_U,
    I32_And,
    I32_Or,
    I32_Xor,
    I32_Shl,
    I32_Shr_S,
    I32_Shr_U,
    I32_Rotl,
    I32_Rotr,
    I64_Clz,
    I64_Ctz,
    I64_Popcnt,
    I64_Add,
    I64_Sub,
    I64_Mul,
    I64_Div_S,
    I64_Div_U,
    I64_Rem_S,
    I64_Rem_U,
    I64_And,
    I64_Or,
    I64_Xor,
    I64_Shl,
    I64_Shr_S,
    I64_Shr_U,
    I64_Rotl,
    I64_Rotr,
    F32_Abs,
    F32_Neg,
    F32_Ceil,
    F32_Floor,
    F32_Trunc,
    F32_Nearest,
    F32_Sqrt,
    F32_Add,
    F32_Sub,
    F32_Mul,
    F32_Div,
    F32_Min,
    F32_Max,
    F32_Copysign,
    F64_Abs,
    F64_Neg,
    F64_Ceil,
    F64_Floor,
    F64_Trunc,
    F64_Nearest,
    F64_Sqrt,
    F64_Add,
    F64_Sub,
    F64_Mul,
    F64_Div,
    F64_Min,
    F64_Max,
    F64_Copysign,
    I32_Wrap_I64,
    I32_Trunc_F32_S,
    I32_Trunc_F32_U,
    I32_Trunc_F64_S,
    I32_Trunc_F64_U,
    I64_Extend_I32_S,
    I64_Extend_I32_U,
    I64_Trunc_F32_S,
    I64_Trunc_F32_U,
    I64_Trunc_F64_S,
    I64_Trunc_F64_U,
    F32_Convert_I32_S,
    F32_Convert_I32_U,
    F32_Convert_I64_S,
    F32_Convert_I64_U,
    F32_Demote_F64,
    F64_Convert_I32_S,
    F64_Convert_I32_U,
    F64_Convert_I64_S,
    F64_Convert_I64_U,
    F64_Promote_F32,
    I32_Reinterpret_F32,
    I64_Reinterpret_F64,
    F32_Reinterpret_I32,
    F64_Reinterpret_I64,
    I32_Extend8_S,
    I32_Extend16_S,
    I64_Extend8_S,
    I64_Extend16_S,
    I64_Extend32_S,
    Ref_Null,
    Ref_Is_Null,
    Ref_Func,
    I32_Trunc_Sat_F32_S,
    I32_Trunc_Sat_F32_U,
    I32_Trunc_Sat_F64_S,
    I32_Trunc_Sat_F64_U,
    I64_Trunc_Sat_F32_S,
    I64_Trunc_Sat_F32_U,
    I64_Trunc_Sat_F64_S,
    I64_Trunc_Sat_F64_U,
    Memory_Init,
    Data_Drop,
    Memory_Copy,
    Memory_Fill,
    Table_Init,
    Elem_Drop,
    Table_Copy,
    Table_Grow,
    Table_Size,
    Table_Fill,

    pub fn beginsBlock(opcode: Opcode) bool {
        return switch (opcode) {
            .Block => true,
            .Loop => true,
            .If => true,
            else => false,
        };
    }

    pub fn isIf(opcode: Opcode) bool {
        return switch (opcode) {
            .If, .IfNoElse => true,
            else => false,
        };
    }
};

pub const WasmOpcode = enum(u16) {
    Unreachable = 0x00,
    Noop = 0x01,
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    End = 0x0B,
    Branch = 0x0C,
    Branch_If = 0x0D,
    Branch_Table = 0x0E,
    Return = 0x0F,
    Call = 0x10,
    Call_Indirect = 0x11,
    Drop = 0x1A,
    Select = 0x1B,
    Select_T = 0x1C,
    Local_Get = 0x20,
    Local_Set = 0x21,
    Local_Tee = 0x22,
    Global_Get = 0x23,
    Global_Set = 0x24,
    Table_Get = 0x25,
    Table_Set = 0x26,
    I32_Load = 0x28,
    I64_Load = 0x29,
    F32_Load = 0x2A,
    F64_Load = 0x2B,
    I32_Load8_S = 0x2C,
    I32_Load8_U = 0x2D,
    I32_Load16_S = 0x2E,
    I32_Load16_U = 0x2F,
    I64_Load8_S = 0x30,
    I64_Load8_U = 0x31,
    I64_Load16_S = 0x32,
    I64_Load16_U = 0x33,
    I64_Load32_S = 0x34,
    I64_Load32_U = 0x35,
    I32_Store = 0x36,
    I64_Store = 0x37,
    F32_Store = 0x38,
    F64_Store = 0x39,
    I32_Store8 = 0x3A,
    I32_Store16 = 0x3B,
    I64_Store8 = 0x3C,
    I64_Store16 = 0x3D,
    I64_Store32 = 0x3E,
    Memory_Size = 0x3F,
    Memory_Grow = 0x40,
    I32_Const = 0x41,
    I64_Const = 0x42,
    F32_Const = 0x43,
    F64_Const = 0x44,
    I32_Eqz = 0x45,
    I32_Eq = 0x46,
    I32_NE = 0x47,
    I32_LT_S = 0x48,
    I32_LT_U = 0x49,
    I32_GT_S = 0x4A,
    I32_GT_U = 0x4B,
    I32_LE_S = 0x4C,
    I32_LE_U = 0x4D,
    I32_GE_S = 0x4E,
    I32_GE_U = 0x4F,
    I64_Eqz = 0x50,
    I64_Eq = 0x51,
    I64_NE = 0x52,
    I64_LT_S = 0x53,
    I64_LT_U = 0x54,
    I64_GT_S = 0x55,
    I64_GT_U = 0x56,
    I64_LE_S = 0x57,
    I64_LE_U = 0x58,
    I64_GE_S = 0x59,
    I64_GE_U = 0x5A,
    F32_EQ = 0x5B,
    F32_NE = 0x5C,
    F32_LT = 0x5D,
    F32_GT = 0x5E,
    F32_LE = 0x5F,
    F32_GE = 0x60,
    F64_EQ = 0x61,
    F64_NE = 0x62,
    F64_LT = 0x63,
    F64_GT = 0x64,
    F64_LE = 0x65,
    F64_GE = 0x66,
    I32_Clz = 0x67,
    I32_Ctz = 0x68,
    I32_Popcnt = 0x69,
    I32_Add = 0x6A,
    I32_Sub = 0x6B,
    I32_Mul = 0x6C,
    I32_Div_S = 0x6D,
    I32_Div_U = 0x6E,
    I32_Rem_S = 0x6F,
    I32_Rem_U = 0x70,
    I32_And = 0x71,
    I32_Or = 0x72,
    I32_Xor = 0x73,
    I32_Shl = 0x74,
    I32_Shr_S = 0x75,
    I32_Shr_U = 0x76,
    I32_Rotl = 0x77,
    I32_Rotr = 0x78,
    I64_Clz = 0x79,
    I64_Ctz = 0x7A,
    I64_Popcnt = 0x7B,
    I64_Add = 0x7C,
    I64_Sub = 0x7D,
    I64_Mul = 0x7E,
    I64_Div_S = 0x7F,
    I64_Div_U = 0x80,
    I64_Rem_S = 0x81,
    I64_Rem_U = 0x82,
    I64_And = 0x83,
    I64_Or = 0x84,
    I64_Xor = 0x85,
    I64_Shl = 0x86,
    I64_Shr_S = 0x87,
    I64_Shr_U = 0x88,
    I64_Rotl = 0x89,
    I64_Rotr = 0x8A,
    F32_Abs = 0x8B,
    F32_Neg = 0x8C,
    F32_Ceil = 0x8D,
    F32_Floor = 0x8E,
    F32_Trunc = 0x8F,
    F32_Nearest = 0x90,
    F32_Sqrt = 0x91,
    F32_Add = 0x92,
    F32_Sub = 0x93,
    F32_Mul = 0x94,
    F32_Div = 0x95,
    F32_Min = 0x96,
    F32_Max = 0x97,
    F32_Copysign = 0x98,
    F64_Abs = 0x99,
    F64_Neg = 0x9A,
    F64_Ceil = 0x9B,
    F64_Floor = 0x9C,
    F64_Trunc = 0x9D,
    F64_Nearest = 0x9E,
    F64_Sqrt = 0x9F,
    F64_Add = 0xA0,
    F64_Sub = 0xA1,
    F64_Mul = 0xA2,
    F64_Div = 0xA3,
    F64_Min = 0xA4,
    F64_Max = 0xA5,
    F64_Copysign = 0xA6,
    I32_Wrap_I64 = 0xA7,
    I32_Trunc_F32_S = 0xA8,
    I32_Trunc_F32_U = 0xA9,
    I32_Trunc_F64_S = 0xAA,
    I32_Trunc_F64_U = 0xAB,
    I64_Extend_I32_S = 0xAC,
    I64_Extend_I32_U = 0xAD,
    I64_Trunc_F32_S = 0xAE,
    I64_Trunc_F32_U = 0xAF,
    I64_Trunc_F64_S = 0xB0,
    I64_Trunc_F64_U = 0xB1,
    F32_Convert_I32_S = 0xB2,
    F32_Convert_I32_U = 0xB3,
    F32_Convert_I64_S = 0xB4,
    F32_Convert_I64_U = 0xB5,
    F32_Demote_F64 = 0xB6,
    F64_Convert_I32_S = 0xB7,
    F64_Convert_I32_U = 0xB8,
    F64_Convert_I64_S = 0xB9,
    F64_Convert_I64_U = 0xBA,
    F64_Promote_F32 = 0xBB,
    I32_Reinterpret_F32 = 0xBC,
    I64_Reinterpret_F64 = 0xBD,
    F32_Reinterpret_I32 = 0xBE,
    F64_Reinterpret_I64 = 0xBF,
    I32_Extend8_S = 0xC0,
    I32_Extend16_S = 0xC1,
    I64_Extend8_S = 0xC2,
    I64_Extend16_S = 0xC3,
    I64_Extend32_S = 0xC4,
    Ref_Null = 0xD0,
    Ref_Is_Null = 0xD1,
    Ref_Func = 0xD2,
    I32_Trunc_Sat_F32_S = 0xFC00,
    I32_Trunc_Sat_F32_U = 0xFC01,
    I32_Trunc_Sat_F64_S = 0xFC02,
    I32_Trunc_Sat_F64_U = 0xFC03,
    I64_Trunc_Sat_F32_S = 0xFC04,
    I64_Trunc_Sat_F32_U = 0xFC05,
    I64_Trunc_Sat_F64_S = 0xFC06,
    I64_Trunc_Sat_F64_U = 0xFC07,
    Memory_Init = 0xFC08,
    Data_Drop = 0xFC09,
    Memory_Copy = 0xFC0A,
    Memory_Fill = 0xFC0B,
    Table_Init = 0xFC0C,
    Elem_Drop = 0xFC0D,
    Table_Copy = 0xFC0E,
    Table_Grow = 0xFC0F,
    Table_Size = 0xFC10,
    Table_Fill = 0xFC11,

    pub fn toOpcode(wasm: WasmOpcode) Opcode {
        const opcode_int = @enumToInt(wasm);
        const opcode: Opcode = if (opcode_int < ConversionTables.wasmOpcodeToOpcodeTable.len) ConversionTables.wasmOpcodeToOpcodeTable[opcode_int] else ConversionTables.wasmFCOpcodeToOpcodeTable[opcode_int - 0xFC00];
        std.debug.assert(opcode != .Invalid);
        return opcode;
    }
};

const ConversionTables = struct {
    const wasmOpcodeToOpcodeTable = [_]Opcode{
        Opcode.Unreachable, // 0x00
        Opcode.Noop, // 0x01
        Opcode.Block, // 0x02
        Opcode.Loop, // 0x03
        Opcode.If, // 0x04
        Opcode.Else, // 0x05
        Opcode.Invalid, // 0x06
        Opcode.Invalid, // 0x07
        Opcode.Invalid, // 0x08
        Opcode.Invalid, // 0x09
        Opcode.Invalid, // 0x0A
        Opcode.End, // 0x0B,
        Opcode.Branch, // 0x0C
        Opcode.Branch_If, // 0x0D
        Opcode.Branch_Table, // 0x0E
        Opcode.Return, // 0x0F
        Opcode.Call, // 0x10
        Opcode.Call_Indirect, // 0x11
        Opcode.Invalid, // 0x12
        Opcode.Invalid, // 0x13
        Opcode.Invalid, // 0x14
        Opcode.Invalid, // 0x15
        Opcode.Invalid, // 0x16
        Opcode.Invalid, // 0x17
        Opcode.Invalid, // 0x18
        Opcode.Invalid, // 0x19
        Opcode.Drop, // 0x1A
        Opcode.Select, // 0x1B
        Opcode.Select_T, // 0x1C
        Opcode.Invalid, // 0x1D
        Opcode.Invalid, // 0x1E
        Opcode.Invalid, // 0x1F
        Opcode.Local_Get, // 0x20
        Opcode.Local_Set, // 0x21
        Opcode.Local_Tee, // 0x22
        Opcode.Global_Get, // 0x23
        Opcode.Global_Set, // 0x24
        Opcode.Table_Get, // 0x25
        Opcode.Table_Set, // 0x26
        Opcode.Invalid, // 0x27
        Opcode.I32_Load, // 0x28
        Opcode.I64_Load, // 0x29
        Opcode.F32_Load, // 0x2A
        Opcode.F64_Load, // 0x2B
        Opcode.I32_Load8_S, // 0x2C
        Opcode.I32_Load8_U, // 0x2D
        Opcode.I32_Load16_S, // 0x2E
        Opcode.I32_Load16_U, // 0x2F
        Opcode.I64_Load8_S, // 0x30
        Opcode.I64_Load8_U, // 0x31
        Opcode.I64_Load16_S, // 0x32
        Opcode.I64_Load16_U, // 0x33
        Opcode.I64_Load32_S, // 0x34
        Opcode.I64_Load32_U, // 0x35
        Opcode.I32_Store, // 0x36
        Opcode.I64_Store, // 0x37
        Opcode.F32_Store, // 0x38
        Opcode.F64_Store, // 0x39
        Opcode.I32_Store8, // 0x3A
        Opcode.I32_Store16, // 0x3B
        Opcode.I64_Store8, // 0x3C
        Opcode.I64_Store16, // 0x3D
        Opcode.I64_Store32, // 0x3E
        Opcode.Memory_Size, // 0x3F
        Opcode.Memory_Grow, // 0x40
        Opcode.I32_Const, // 0x41
        Opcode.I64_Const, // 0x42
        Opcode.F32_Const, // 0x43
        Opcode.F64_Const, // 0x44
        Opcode.I32_Eqz, // 0x45
        Opcode.I32_Eq, // 0x46
        Opcode.I32_NE, // 0x47
        Opcode.I32_LT_S, // 0x48
        Opcode.I32_LT_U, // 0x49
        Opcode.I32_GT_S, // 0x4A
        Opcode.I32_GT_U, // 0x4B
        Opcode.I32_LE_S, // 0x4C
        Opcode.I32_LE_U, // 0x4D
        Opcode.I32_GE_S, // 0x4E
        Opcode.I32_GE_U, // 0x4F
        Opcode.I64_Eqz, // 0x50
        Opcode.I64_Eq, // 0x51
        Opcode.I64_NE, // 0x52
        Opcode.I64_LT_S, // 0x53
        Opcode.I64_LT_U, // 0x54
        Opcode.I64_GT_S, // 0x55
        Opcode.I64_GT_U, // 0x56
        Opcode.I64_LE_S, // 0x57
        Opcode.I64_LE_U, // 0x58
        Opcode.I64_GE_S, // 0x59
        Opcode.I64_GE_U, // 0x5A
        Opcode.F32_EQ, // 0x5B
        Opcode.F32_NE, // 0x5C
        Opcode.F32_LT, // 0x5D
        Opcode.F32_GT, // 0x5E
        Opcode.F32_LE, // 0x5F
        Opcode.F32_GE, // 0x60
        Opcode.F64_EQ, // 0x61
        Opcode.F64_NE, // 0x62
        Opcode.F64_LT, // 0x63
        Opcode.F64_GT, // 0x64
        Opcode.F64_LE, // 0x65
        Opcode.F64_GE, // 0x66
        Opcode.I32_Clz, // 0x67
        Opcode.I32_Ctz, // 0x68
        Opcode.I32_Popcnt, // 0x69
        Opcode.I32_Add, // 0x6A
        Opcode.I32_Sub, // 0x6B
        Opcode.I32_Mul, // 0x6C
        Opcode.I32_Div_S, // 0x6D
        Opcode.I32_Div_U, // 0x6E
        Opcode.I32_Rem_S, // 0x6F
        Opcode.I32_Rem_U, // 0x70
        Opcode.I32_And, // 0x71
        Opcode.I32_Or, // 0x72
        Opcode.I32_Xor, // 0x73
        Opcode.I32_Shl, // 0x74
        Opcode.I32_Shr_S, // 0x75
        Opcode.I32_Shr_U, // 0x76
        Opcode.I32_Rotl, // 0x77
        Opcode.I32_Rotr, // 0x78
        Opcode.I64_Clz, // 0x79
        Opcode.I64_Ctz, // 0x7A
        Opcode.I64_Popcnt, // 0x7B
        Opcode.I64_Add, // 0x7C
        Opcode.I64_Sub, // 0x7D
        Opcode.I64_Mul, // 0x7E
        Opcode.I64_Div_S, // 0x7F
        Opcode.I64_Div_U, // 0x80
        Opcode.I64_Rem_S, // 0x81
        Opcode.I64_Rem_U, // 0x82
        Opcode.I64_And, // 0x83
        Opcode.I64_Or, // 0x84
        Opcode.I64_Xor, // 0x85
        Opcode.I64_Shl, // 0x86
        Opcode.I64_Shr_S, // 0x87
        Opcode.I64_Shr_U, // 0x88
        Opcode.I64_Rotl, // 0x89
        Opcode.I64_Rotr, // 0x8A
        Opcode.F32_Abs, // 0x8B
        Opcode.F32_Neg, // 0x8C
        Opcode.F32_Ceil, // 0x8D
        Opcode.F32_Floor, // 0x8E
        Opcode.F32_Trunc, // 0x8F
        Opcode.F32_Nearest, // 0x90
        Opcode.F32_Sqrt, // 0x91
        Opcode.F32_Add, // 0x92
        Opcode.F32_Sub, // 0x93
        Opcode.F32_Mul, // 0x94
        Opcode.F32_Div, // 0x95
        Opcode.F32_Min, // 0x96
        Opcode.F32_Max, // 0x97
        Opcode.F32_Copysign, // 0x98
        Opcode.F64_Abs, // 0x99
        Opcode.F64_Neg, // 0x9A
        Opcode.F64_Ceil, // 0x9B
        Opcode.F64_Floor, // 0x9C
        Opcode.F64_Trunc, // 0x9D
        Opcode.F64_Nearest, // 0x9E
        Opcode.F64_Sqrt, // 0x9F
        Opcode.F64_Add, // 0xA0
        Opcode.F64_Sub, // 0xA1
        Opcode.F64_Mul, // 0xA2
        Opcode.F64_Div, // 0xA3
        Opcode.F64_Min, // 0xA4
        Opcode.F64_Max, // 0xA5
        Opcode.F64_Copysign, // 0xA6
        Opcode.I32_Wrap_I64, // 0xA7
        Opcode.I32_Trunc_F32_S, // 0xA8
        Opcode.I32_Trunc_F32_U, // 0xA9
        Opcode.I32_Trunc_F64_S, // 0xAA
        Opcode.I32_Trunc_F64_U, // 0xAB
        Opcode.I64_Extend_I32_S, // 0xAC
        Opcode.I64_Extend_I32_U, // 0xAD
        Opcode.I64_Trunc_F32_S, // 0xAE
        Opcode.I64_Trunc_F32_U, // 0xAF
        Opcode.I64_Trunc_F64_S, // 0xB0
        Opcode.I64_Trunc_F64_U, // 0xB1
        Opcode.F32_Convert_I32_S, // 0xB2
        Opcode.F32_Convert_I32_U, // 0xB3
        Opcode.F32_Convert_I64_S, // 0xB4
        Opcode.F32_Convert_I64_U, // 0xB5
        Opcode.F32_Demote_F64, // 0xB6
        Opcode.F64_Convert_I32_S, // 0xB7
        Opcode.F64_Convert_I32_U, // 0xB8
        Opcode.F64_Convert_I64_S, // 0xB9
        Opcode.F64_Convert_I64_U, // 0xBA
        Opcode.F64_Promote_F32, // 0xBB
        Opcode.I32_Reinterpret_F32, // 0xBC
        Opcode.I64_Reinterpret_F64, // 0xBD
        Opcode.F32_Reinterpret_I32, // 0xBE
        Opcode.F64_Reinterpret_I64, // 0xBF
        Opcode.I32_Extend8_S, // 0xC0
        Opcode.I32_Extend16_S, // 0xC1
        Opcode.I64_Extend8_S, // 0xC2
        Opcode.I64_Extend16_S, // 0xC3
        Opcode.I64_Extend32_S, // 0xC4
        Opcode.Invalid, // 0xC5
        Opcode.Invalid, // 0xC6
        Opcode.Invalid, // 0xC7
        Opcode.Invalid, // 0xC8
        Opcode.Invalid, // 0xC9
        Opcode.Invalid, // 0xCA
        Opcode.Invalid, // 0xCB
        Opcode.Invalid, // 0xCC
        Opcode.Invalid, // 0xCD
        Opcode.Invalid, // 0xCE
        Opcode.Invalid, // 0xCF
        Opcode.Ref_Null, // 0xD0
        Opcode.Ref_Is_Null, // 0xD1
        Opcode.Ref_Func, // 0xD2
    };

    const wasmFCOpcodeToOpcodeTable = [_]Opcode{
        Opcode.I32_Trunc_Sat_F32_S, // 0xFC00
        Opcode.I32_Trunc_Sat_F32_U, // 0xFC01
        Opcode.I32_Trunc_Sat_F64_S, // 0xFC02
        Opcode.I32_Trunc_Sat_F64_U, // 0xFC03
        Opcode.I64_Trunc_Sat_F32_S, // 0xFC04
        Opcode.I64_Trunc_Sat_F32_U, // 0xFC05
        Opcode.I64_Trunc_Sat_F64_S, // 0xFC06
        Opcode.I64_Trunc_Sat_F64_U, // 0xFC07
        Opcode.Memory_Init, // 0xFC08
        Opcode.Data_Drop, // 0xFC09
        Opcode.Memory_Copy, // 0xFC0A
        Opcode.Memory_Fill, // 0xFC0B
        Opcode.Table_Init, // 0xFC0C
        Opcode.Elem_Drop, // 0xFC0D
        Opcode.Table_Copy, // 0xFC0E
        Opcode.Table_Grow, // 0xFC0F
        Opcode.Table_Size, // 0xFC10
        Opcode.Table_Fill, // 0xFC11
    };
};
