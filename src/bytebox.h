// C interface for bytebox wasm runtime.

#include <stdint.h>
#include <stdbool.h>

struct bb_slice
{
	char* data;
	size_t length;
};
typedef struct bb_slice bb_slice;

enum bb_error
{
	BB_ERROR_OK,
	BB_ERROR_FAILED,
	BB_ERROR_OUTOFMEMORY,
	BB_ERROR_INVALIDPARAM,
};
typedef enum bb_error bb_error;

enum bb_valtype
{
    BB_VALTYPE_I32,
    BB_VALTYPE_I64,
    BB_VALTYPE_F32,
    BB_VALTYPE_F64,
};
typedef enum bb_valtype bb_valtype;

typedef float[4] bb_v128;
union bb_val
{
	int32_t i32_val;
	int64_t i64_val;
	float f32_val;
	double f64_val;
	bb_v128 v128_val;
	uint32 externref_val;
};
typedef union bb_val bb_val;

struct bb_module_definition_init_opts
{
	const char* debug_name;
};
typedef struct bb_module_definition_init_opts bb_module_definition_init_opts;

struct bb_module_definition
{
	void* module;
};
typedef struct bb_module_definition bb_module_definition;

typedef void bb_host_function(void* userdata, bb_module_instance* module, const bb_val* params, bb_val* returns);

struct bb_import_function
{
	const char* name;
	bb_host_function* func;
	bb_valtype* params;
	size_t num_params;
	bb_valtype* returns;
	size_t num_returns;
	void* userdata;
};
typedef struct bb_import_function bb_import_function;

struct bb_import_package
{
	const char* name; // must be valid. Use "*" to try to match any module imports
	bb_import_function* functions;
	size_t num_functions;

	// TODO globals, tables, memories
};
typedef struct bb_import_package bb_import_package;

struct bb_module_instance_instantiate_opts
{
	bb_import_package* packages;
	size_t num_packages;
	bool enable_debug;
};
typedef struct bb_module_instance_instantiate_opts bb_module_instance_instantiate_opts;

struct bb_module_instance
{
	void* module;
};
typedef struct bb_module_instance bb_module_instance;

struct bb_module_instance_invoke_opts
{
	bool trap_on_start;
};
typedef struct bb_module_instance_invoke_opts bb_module_instance_invoke_opts;

enum bb_debug_trap_mode
{
	BB_DEBUG_TRAP_MODE_DISABLED,
	BB_DEBUG_TRAP_MODE_ENABLED,
};
typedef enum bb_debug_trap_mode bb_debug_trap_mode;

// struct bb_val_tagged
// {
// 	bb_valtype type;
// 	bb_val val;
// };
// typedef struct bb_val_tagged bb_val_tagged;

// typedef void* bb_malloc_func(size_t size, void* userdata);
// typedef void* bb_realloc_func(void* mem, size_t size, void* userdata);
// typedef void bb_free_func(void* mem, void* userdata);

// void bb_set_memory_hooks(bb_alloc_func* alloc_func, bb_realloc_func* realloc_func, bb_free_func);

bb_module_definition bb_module_definition_init(bb_module_definition_init_opts opts);
void bb_module_definition_deinit(bb_module_definition* definition);
bb_error bb_module_definition_decode(bb_module_definition* definition, const char* data, size_t length);
bb_slice bb_module_definition_get_custom_section(const bb_module_definition* definition, const char* name);

bb_module_instance bb_module_instance_init(bb_module_definition* definition);
void bb_module_instance_deinit(bb_module_instance* instance);
bb_error bb_module_instance_instantiate(bb_module_instance* instance, bb_module_instance_instantiate_opts opts);
bb_error bb_module_instance_invoke(bb_module_instance* instance, const char* func_name, const bb_val* params, size_t num_params, bb_val* returns, size_t num_returns, bb_module_instance_invoke_opts opts);
bb_error bb_module_instance_resume(bb_module_instance* instance, bb_val* returns, size_t num_returns);
bb_error bb_module_instance_step(bb_module_instance* instance, bb_val* returns, size_t num_returns);
bb_error bb_module_instance_debug_set_trap(bb_module_instance* instance, uint32_t address, bb_debug_trap_mode trap_mode);
