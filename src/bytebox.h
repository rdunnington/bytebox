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
	BB_ERROR_UNKNOWNEXPORT,
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

typedef float bb_v128[4];
union bb_val
{
	int32_t i32_val;
	int64_t i64_val;
	float f32_val;
	double f64_val;
	bb_v128 v128_val;
	uint32_t externref_val;
};
typedef union bb_val bb_val;

struct bb_module_definition_init_opts
{
	const char* debug_name;
};
typedef struct bb_module_definition_init_opts bb_module_definition_init_opts;

typedef struct bb_module_definition bb_module_definition;
typedef struct bb_module_instance bb_module_instance;
typedef struct bb_import_package bb_import_package;

struct bb_module_instance_instantiate_opts
{
	bb_import_package** packages;
	size_t num_packages;
	bool enable_debug;
};
typedef struct bb_module_instance_instantiate_opts bb_module_instance_instantiate_opts;

struct bb_module_instance_invoke_opts
{
	bool trap_on_start;
};
typedef struct bb_module_instance_invoke_opts bb_module_instance_invoke_opts;

struct bb_func_handle
{
	uint32_t index;
	uint32_t type;
};
typedef struct bb_func_handle bb_func_handle;

struct bb_func_info
{
	bb_valtype* params;
	size_t num_params;
	bb_valtype* returns;
	size_t num_returns;
};
typedef struct bb_func_info bb_func_info;

enum bb_debug_trap_mode
{
	BB_DEBUG_TRAP_MODE_DISABLED,
	BB_DEBUG_TRAP_MODE_ENABLED,
};
typedef enum bb_debug_trap_mode bb_debug_trap_mode;

typedef void bb_host_function(void* userdata, bb_module_instance* module, const bb_val* params, bb_val* returns);

// typedef void* bb_malloc_func(size_t size, void* userdata);
// typedef void* bb_realloc_func(void* mem, size_t size, void* userdata);
// typedef void bb_free_func(void* mem, void* userdata);

// void bb_set_memory_hooks(bb_alloc_func* alloc_func, bb_realloc_func* realloc_func, bb_free_func);

const char* bb_error_str(bb_error err);

bb_module_definition* bb_module_definition_init(bb_module_definition_init_opts opts);
void bb_module_definition_deinit(bb_module_definition* definition);
bb_error bb_module_definition_decode(bb_module_definition* definition, const char* data, size_t length);
bb_slice bb_module_definition_get_custom_section(const bb_module_definition* definition, const char* name);

bb_import_package* bb_import_package_init(const char* name);
void bb_import_package_deinit(bb_import_package* package); // only deinit when all module_instances using the package have been deinited
bb_error bb_import_package_add_function(bb_import_package* package, bb_host_function* func, const char* export_name, bb_valtype* params, size_t num_params, bb_valtype* returns, size_t num_returns, void* userdata);

bb_module_instance* bb_module_instance_init(bb_module_definition* definition);
void bb_module_instance_deinit(bb_module_instance* instance);
bb_error bb_module_instance_instantiate(bb_module_instance* instance, bb_module_instance_instantiate_opts opts);
bb_error bb_module_instance_find_func(bb_module_instance* instance, const char* func_name, bb_func_handle* out_handle);
bb_func_info bb_module_instance_func_info(bb_module_instance* instance, bb_func_handle handle);
bb_error bb_module_instance_invoke(bb_module_instance* instance, bb_func_handle, const bb_val* params, size_t num_params, bb_val* returns, size_t num_returns, bb_module_instance_invoke_opts opts);
bb_error bb_module_instance_resume(bb_module_instance* instance, bb_val* returns, size_t num_returns);
bb_error bb_module_instance_step(bb_module_instance* instance, bb_val* returns, size_t num_returns);
bb_error bb_module_instance_debug_set_trap(bb_module_instance* instance, uint32_t address, bb_debug_trap_mode trap_mode);
void* bb_module_instance_mem(bb_module_instance* instance, size_t offset, size_t length);
bb_slice bb_module_instance_mem_all(bb_module_instance* instance);

bool bb_func_handle_isvalid(bb_func_handle handle);
