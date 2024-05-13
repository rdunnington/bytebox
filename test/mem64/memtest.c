// clang --target=wasm64-freestanding -mbulk-memory -nostdlib -O2 -Wl,--no-entry -Wl,--export-dynamic -o memtest.wasm memtest.c

#include <stddef.h>
#include <stdint.h>

#define KB ((size_t)1024)
#define MB (1024 * KB)
#define GB (1024 * MB)

#define PAGE_SIZE (64 * KB)
#define PAGES_PER_GB (GB / PAGE_SIZE)

#define assert(value) if (value == 0) return -1

__attribute__((visibility("default"))) int64_t memtest(int32_t val_i32, int64_t val_i64, float val_f32, double val_f64)
{
	int64_t start_page = __builtin_wasm_memory_grow(0, PAGES_PER_GB * 2); // memory.grow
	assert(start_page != -1);

	char* mem = (char*)(start_page);
	volatile char* mem_stores = mem + MB * 1;
	volatile char* mem_loads = mem + MB * 2;

	int64_t num_pages = __builtin_wasm_memory_size(0); // memory.size
	assert(num_pages >= (PAGES_PER_GB * 2));

	*(int32_t*)(mem_loads + 0) = val_i32; // i32.store
	*(int64_t*)(mem_loads + 8) = val_i64; // i64.store
	*(float*)(mem_loads + 16) = val_f32; // f32.store
	*(double*)(mem_loads + 24) = val_f64; // f64.store

	*(int32_t*)(mem_stores + 0) = *(int32_t*)(mem_loads + 0); // i32.load -> i32.store
	*(int64_t*)(mem_stores + 8) = *(int64_t*)(mem_loads + 8); // i64.load -> i64.store
	*(float*)(mem_stores + 16)  = *(float*)(mem_loads + 16); // f32.load -> f32.store
	*(double*)(mem_stores + 24) = *(double*)(mem_loads + 24); // f64.load -> f64.store

	assert(*(int32_t*)(mem_stores + 0) == val_i32);
	assert(*(int64_t*)(mem_stores + 8) == val_i64);
	assert(*(float*)(mem_stores + 16) == val_f32);
	assert(*(double*)(mem_stores + 24) == val_f64);

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

	return 0;
}
