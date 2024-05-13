// clang --target=wasm64-freestanding -mbulk-memory -nostdlib -O2 -Wl,--no-entry -Wl,--export-dynamic -o memtest.wasm memtest.c

#include <stddef.h>
#include <stdint.h>

#define KB ((size_t)1024)
#define MB (1024 * KB)
#define GB (1024 * MB)

#define PAGE_SIZE (64 * KB)
#define PAGES_PER_GB (GB / PAGE_SIZE)

void assert(int value)
{
	if (value == 0)
	{
		__builtin_trap();
	}
}

__attribute__((visibility("default"))) void memtest(int32_t val_i32, int64_t val_i64, float val_f32, double val_f64)
{
	__builtin_wasm_memory_grow(0, PAGES_PER_GB * 8); // memory.grow
	char* mem = (char*)(GB * 4);
	char* mem_stores = (char*)(GB * 5);
	char* mem_loads = (char*)(GB * 6);

	size_t num_pages = __builtin_wasm_memory_size(0); // memory.size
	assert(num_pages == (PAGES_PER_GB * 8));

	*(int32_t*)(mem_stores + 0) = *(int32_t*)(mem_loads + 0); // i32.load -> i32.store
	*(int64_t*)(mem_stores + 8) = *(int64_t*)(mem_loads + 8); // i64.load -> i64.store
	*(float*)(mem_stores + 16)  = *(float*)(mem_loads + 16); // f32.load -> f32.store
	*(double*)(mem_stores + 24) = *(double*)(mem_loads + 24); // f64.load -> f64.store

	*(int8_t*)(mem_stores + 32) = (int8_t)val_i32; // i32.store8
	*(int16_t*)(mem_stores + 40) = (int16_t)val_i32; // i32.store16
	*(int8_t*)(mem_stores + 48) = (int8_t)val_i64; // i64.store8
	*(int16_t*)(mem_stores + 56) = (int16_t)val_i64; // i64.store16
	*(int32_t*)(mem_stores + 64) = (int32_t)val_i64; // i64.store32

	int32_t store32 = 0;
	store32 += (int32_t)*(int8_t*)(mem_loads + 32); // i32.load8_s
	store32 += (int32_t)*(uint8_t*)(mem_loads + 40); // i32.load8_u
	store32 += (int32_t)*(int16_t*)(mem_loads + 48); // i32.load16_s
	store32 += (int32_t)*(uint16_t*)(mem_loads + 56); // i32.load16_s

	int64_t store64 = 0;
	store64 += (int64_t)*(int8_t*)(mem_loads + 64); // i64.load8_s
	store64 += (int64_t)*(uint8_t*)(mem_loads + 72); // i64.load8_u
	store64 += (int64_t)*(int16_t*)(mem_loads + 80); // i64.load16_s
	store64 += (int64_t)*(uint16_t*)(mem_loads + 88); // i64.load16_s
	store64 += (int64_t)*(int32_t*)(mem_loads + 96); // i64.load32_s
	store64 += (int64_t)*(uint32_t*)(mem_loads + 104); // i64.load32_s

	// forces the compiler to not elide or condense the loads
	*(int32_t*)(mem_stores + 0) = store32;
	*(int64_t*)(mem_stores + 8) = store64;
	
	__builtin_memset(mem + KB, 0xFF, KB); // memory.fill
	__builtin_memcpy(mem + KB * 4, mem + KB * 3, KB); // memory.copy
}
