#include <stdio.h>
#include "bytebox.h"

void magic(void *userdata, bb_module_instance *inst, const bb_val *params, bb_val *returns) {
  int *data = (int *)userdata;

  returns[0].i32_val = *data;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    return -1;
  }

  char *path = argv[2];
  bb_module_definition_init_opts mod_opts;
  mod_opts.debug_name = "test-cffi";

  bb_module_definition *mod_def = bb_module_definition_create(mod_opts);

  bb_import_package *imports[1];
  imports[0] = bb_import_package_init("env");
  bb_error err;

  int magic_num = 40;
  bb_valtype magic_returns[1];
  magic_returns[0] = BB_VALTYPE_I32;

  bb_import_function magic_func;
  magic_func.callback = &magic;
  magic_func.userdata = (void *)&magic_num;

  err = bb_import_package_add_function(imports[0], "magic", NULL, 0, magic_returns, 1, &magic_func);

  bb_module_instance *mod_inst = bb_module_instance_create(mod_def);

  bb_module_instance_instantiate_opts inst_opts = {0};
  inst_opts.packages = imports;
  inst_opts.num_packages = 1;

  err = bb_module_instance_instantiate(mod_inst, inst_opts);
  if (err != BB_ERROR_OK) {
    fprintf(stderr, "Instantiation failed with %d %s\n", err, bb_error_str(err));
    goto cleanup;
  }

  bb_func_handle entry;
  err = bb_module_instance_find_func(mod_inst, "entry", &entry);

  if (err != BB_ERROR_OK) {
    fprintf(stderr, "Failed to find function 'entry': %d %s\n", err, bb_error_str(err));
    goto cleanup;
  }

  bb_module_instance_invoke_opts invoke_opts = {0};
  bb_val returns[1];
  err = bb_module_instance_invoke(mod_inst, entry, NULL, 0, &returns, 1, invoke_opts);

  if (err != BB_ERROR_OK) {
    fprintf(stderr, "Error invoking entry: %d %s\n", err, bb_error_str(err));
    goto cleanup;
  }

  if (returns[0].i32_val != 42) {
    err = -42;
  } else {
    err = BB_ERROR_OK;
  }

cleanup:
  bb_module_instance_destroy(mod_inst);
  bb_import_package_deinit(imports[0]);
  bb_module_definition_destroy(mod_def);

  if (err != BB_ERROR_OK) {
    return err;
  }
  return 0;
}
