extern fn magic() i32;
export fn entry() i32 {
    const magic_num = magic();
    return magic_num + 2;
}
