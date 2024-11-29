/*
 * main.c - Test out kernel space WASM.
 */

#include <linux/module.h>
#include <linux/printk.h>

#include "wasm3.h"
#include "m3_env.h"

#define WASM_STACK_SIZE 64 * 1024 // 64 KB stack

// WASM bytecode (generated by Makefile in wasm directory)
unsigned char wasm_code[] = {
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0d, 0x03, 0x60,
  0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x00, 0x60, 0x00, 0x01, 0x7f, 0x02,
  0x14, 0x01, 0x06, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x09, 0x70, 0x72,
  0x69, 0x6e, 0x74, 0x5f, 0x69, 0x6e, 0x74, 0x00, 0x00, 0x03, 0x03, 0x02,
  0x01, 0x02, 0x05, 0x03, 0x01, 0x00, 0x02, 0x06, 0x3f, 0x0a, 0x7f, 0x01,
  0x41, 0x80, 0x88, 0x04, 0x0b, 0x7f, 0x00, 0x41, 0x80, 0x08, 0x0b, 0x7f,
  0x00, 0x41, 0x80, 0x08, 0x0b, 0x7f, 0x00, 0x41, 0x80, 0x08, 0x0b, 0x7f,
  0x00, 0x41, 0x80, 0x88, 0x04, 0x0b, 0x7f, 0x00, 0x41, 0x80, 0x08, 0x0b,
  0x7f, 0x00, 0x41, 0x80, 0x88, 0x04, 0x0b, 0x7f, 0x00, 0x41, 0x80, 0x80,
  0x08, 0x0b, 0x7f, 0x00, 0x41, 0x00, 0x0b, 0x7f, 0x00, 0x41, 0x01, 0x0b,
  0x07, 0xa7, 0x01, 0x0c, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02,
  0x00, 0x11, 0x5f, 0x5f, 0x77, 0x61, 0x73, 0x6d, 0x5f, 0x63, 0x61, 0x6c,
  0x6c, 0x5f, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x00, 0x01, 0x03, 0x74, 0x77,
  0x6f, 0x00, 0x02, 0x0c, 0x5f, 0x5f, 0x64, 0x73, 0x6f, 0x5f, 0x68, 0x61,
  0x6e, 0x64, 0x6c, 0x65, 0x03, 0x01, 0x0a, 0x5f, 0x5f, 0x64, 0x61, 0x74,
  0x61, 0x5f, 0x65, 0x6e, 0x64, 0x03, 0x02, 0x0b, 0x5f, 0x5f, 0x73, 0x74,
  0x61, 0x63, 0x6b, 0x5f, 0x6c, 0x6f, 0x77, 0x03, 0x03, 0x0c, 0x5f, 0x5f,
  0x73, 0x74, 0x61, 0x63, 0x6b, 0x5f, 0x68, 0x69, 0x67, 0x68, 0x03, 0x04,
  0x0d, 0x5f, 0x5f, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x5f, 0x62, 0x61,
  0x73, 0x65, 0x03, 0x05, 0x0b, 0x5f, 0x5f, 0x68, 0x65, 0x61, 0x70, 0x5f,
  0x62, 0x61, 0x73, 0x65, 0x03, 0x06, 0x0a, 0x5f, 0x5f, 0x68, 0x65, 0x61,
  0x70, 0x5f, 0x65, 0x6e, 0x64, 0x03, 0x07, 0x0d, 0x5f, 0x5f, 0x6d, 0x65,
  0x6d, 0x6f, 0x72, 0x79, 0x5f, 0x62, 0x61, 0x73, 0x65, 0x03, 0x08, 0x0c,
  0x5f, 0x5f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x62, 0x61, 0x73, 0x65,
  0x03, 0x09, 0x0a, 0x1d, 0x02, 0x02, 0x00, 0x0b, 0x18, 0x01, 0x02, 0x7f,
  0x41, 0x03, 0x21, 0x00, 0x20, 0x00, 0x10, 0x80, 0x80, 0x80, 0x80, 0x00,
  0x1a, 0x41, 0x02, 0x21, 0x01, 0x20, 0x01, 0x0f, 0x0b, 0x00, 0x4a, 0x04,
  0x6e, 0x61, 0x6d, 0x65, 0x00, 0x09, 0x08, 0x74, 0x77, 0x6f, 0x2e, 0x77,
  0x61, 0x73, 0x6d, 0x01, 0x24, 0x03, 0x00, 0x09, 0x70, 0x72, 0x69, 0x6e,
  0x74, 0x5f, 0x69, 0x6e, 0x74, 0x01, 0x11, 0x5f, 0x5f, 0x77, 0x61, 0x73,
  0x6d, 0x5f, 0x63, 0x61, 0x6c, 0x6c, 0x5f, 0x63, 0x74, 0x6f, 0x72, 0x73,
  0x02, 0x03, 0x74, 0x77, 0x6f, 0x07, 0x12, 0x01, 0x00, 0x0f, 0x5f, 0x5f,
  0x73, 0x74, 0x61, 0x63, 0x6b, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x65,
  0x72, 0x00, 0x66, 0x09, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x65, 0x72,
  0x73, 0x01, 0x0c, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64,
  0x2d, 0x62, 0x79, 0x01, 0x0c, 0x55, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x20,
  0x63, 0x6c, 0x61, 0x6e, 0x67, 0x3f, 0x31, 0x38, 0x2e, 0x31, 0x2e, 0x38,
  0x20, 0x28, 0x2b, 0x2b, 0x32, 0x30, 0x32, 0x34, 0x30, 0x37, 0x33, 0x31,
  0x30, 0x32, 0x35, 0x30, 0x34, 0x33, 0x2b, 0x33, 0x62, 0x35, 0x62, 0x35,
  0x63, 0x31, 0x65, 0x63, 0x34, 0x61, 0x33, 0x2d, 0x31, 0x7e, 0x65, 0x78,
  0x70, 0x31, 0x7e, 0x32, 0x30, 0x32, 0x34, 0x30, 0x37, 0x33, 0x31, 0x31,
  0x34, 0x35, 0x31, 0x34, 0x34, 0x2e, 0x39, 0x32, 0x29, 0x00, 0x2c, 0x0f,
  0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x66, 0x65, 0x61, 0x74, 0x75,
  0x72, 0x65, 0x73, 0x02, 0x2b, 0x0f, 0x6d, 0x75, 0x74, 0x61, 0x62, 0x6c,
  0x65, 0x2d, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x2b, 0x08, 0x73,
  0x69, 0x67, 0x6e, 0x2d, 0x65, 0x78, 0x74
};
unsigned int wasm_size = 547;


m3ApiRawFunction(print_int)
{
    m3ApiReturnType(int32_t);
    m3ApiGetArg(int32_t, i);

    pr_info("From WASM: %i\n", i);

    m3ApiReturn(0);
}

/*
 * Called when the kernel module is loaded.
 */
int
init_module(void)
{
    // Initialize the Wasm3 environment.
    IM3Environment env = m3_NewEnvironment();
    if (!env) {
        pr_err("Failed to create Wasm3 environment.\n");
        return (-1);
    }

    // Initialize the Wasm3 runtime.
    IM3Runtime runtime = m3_NewRuntime(env, WASM_STACK_SIZE, NULL);
    if (!runtime) {
        pr_err("Failed to create Wasm3 runtime.\n");
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Parse the WASM module.
    IM3Module module;
    M3Result result = m3_ParseModule(env, &module, wasm_code, wasm_size);
    if (result) {
        pr_err("Error parsing module: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Load the WASM module.
    result = m3_LoadModule(runtime, module);
    if (result) {
        pr_err("Error loading module: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Link the print_int() function to the module.
    m3_LinkRawFunction(module, "custom", "print_int", "i(i)", &print_int);

    // Find the WASM function.
    IM3Function func;
    result = m3_FindFunction(&func, runtime, "two");
    if (result) {
        pr_err("Error finding function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Call the WASM function.
    result = m3_CallV(func);
    if (result) {
        pr_err("Error calling function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Fetch the return value.
    uint64_t value = 0;
    result = m3_GetResultsV(func, &value);
    if (result) {
        pr_err("Error getting results: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Print the return value.
    pr_info("Function returned: %lu\n", value);

    // Clean up by freeing the runtime and environment.
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);

    return (0);
}

/*
 * Called when the kernel module is unloaded.
 */
void
cleanup_module(void)
{
    // Just print a goodbye message for now.
    pr_info("Goodbye!\n");
}

MODULE_LICENSE("Dual BSD/GPL");