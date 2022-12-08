export fn run(n: u32) u32 {
    if (n < 2) {
        return 1;
    } else {
        var a = run(n - 1);
        var b = run(n - 2);
        return a + b;
    }
}

// pub fn main() !void {
//     _ = run(7);
// }

// build this with: zig build-lib .\fib.zig -target wasm32-freestanding -dynamic
