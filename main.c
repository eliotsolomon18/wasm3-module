/*
 * main.c - Test out kernel space WASM.
 */

#include <linux/module.h>
#include <linux/printk.h>

#include "wasm3.h"
#include "m3_env.h"

#define WASM_STACK_SIZE 64 * 1024 // 64 KB stack

// Include the WASM bytecode.
#include "wasm/prog.wasm.c"

/*
 * Called by the WASM program to print an integer.
 */
m3ApiRawFunction(print_int)
{
    // Specify the function's signature.
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

    // Find the alloc() WASM function.
    IM3Function alloc_func;
    result = m3_FindFunction(&alloc_func, runtime, "alloc");
    if (result) {
        pr_err("Error finding function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Call the alloc() function.
    result = m3_CallV(alloc_func, 10 * sizeof(int32_t));
    if (result) {
        pr_err("Error calling function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Fetch the alloc() return value.
    uint64_t alloc_value = 0;
    result = m3_GetResultsV(alloc_func, &alloc_value);
    if (result) {
        pr_err("Error getting results: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Compute a pointer to the allocated region.
    int32_t *data = (int32_t *)(m3_GetMemory(runtime, NULL, 0) + alloc_value);

    // Fill the allocated array with values.
    for (int i = 0; i < 10; i++) {
        data[i] = i;
    }

    // Find the sum() WASM function.
    IM3Function sum_func;
    result = m3_FindFunction(&sum_func, runtime, "sum");
    if (result) {
        pr_err("Error finding function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Call the sum() function.
    result = m3_CallV(sum_func);
    if (result) {
        pr_err("Error calling function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Fetch the sum() return value.
    uint64_t sum_value = 0;
    result = m3_GetResultsV(sum_func, &sum_value);
    if (result) {
        pr_err("Error getting results: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return (-1);
    }

    // Print the sum() return value.
    pr_info("Function returned: %lu\n", sum_value);

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