/*
 * main.c - Offer a character device which executes WASM bytecode.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>

#include "wasm3.h"
#include "m3_env.h"

#define WASM_STACK_SIZE (64 * 1024) // 64 KB stack

// The Wasm3 environment shared by all runtimes
IM3Environment env = NULL;

// The Wasm3 runtime lock
DEFINE_SPINLOCK(lock);

// The Wasm3 runtime
IM3Runtime runtime = NULL;

// The Wasm3 module
IM3Module module = NULL;

// The allocation function within the Wasm3 module
IM3Function alloc_func = NULL;

// The sum function within the Wasm3 module
IM3Function sum_func = NULL;

// Device number
static dev_t dev_num;

// Device class
static struct class *dev_class;

// Device
static struct device *dev;

// Character device
static struct cdev cdev;

// Character device write handler
static ssize_t cdev_write(struct file *f, const char __user *buf, size_t len, loff_t *off);

// File operations structure
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .write = cdev_write,
};

// WASM code buffer
char *wasm_code = NULL;

// Size of WASM code buffer
unsigned int wasm_size = 0;

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
static int __init
wasm_init(void)
{
    // Initialize the Wasm3 environment.
    if ((env = m3_NewEnvironment()) == NULL) {
        pr_err("Failed to create Wasm3 environment.\n");
        return -1;
    }

    // Register the device class.
    if (IS_ERR(dev_class = class_create("wasm"))) {
        pr_err("Failed to register the character device class.\n");
        return PTR_ERR(dev_class);
    }

    // Register a character device number.
    if (alloc_chrdev_region(&dev_num, 0, 1, "wasm") < 0) {
        class_destroy(dev_class);
        pr_err("Failed to allocate a character device number.\n");
        return dev_num;
    }

    // Initialize and add the character device.
    cdev_init(&cdev, &fops);
    int ret;
    if ((ret = cdev_add(&cdev, dev_num, 1)) < 0) {
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        pr_err("Failed to add the character device.\n");
        return ret;
    }

    // Register the device node.
    if (IS_ERR(dev = device_create(dev_class, NULL, dev_num, NULL, "wasm"))) {
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        pr_err("Failed to create the character device.\n");
        return PTR_ERR(dev);
    }

    pr_info("Successfully loaded WASM module.\n");

    return 0;
}

void
test(void)
{
    // Call the alloc() function.
    M3Result result;
    if ((result = m3_CallV(alloc_func, 10 * sizeof(int32_t))) != NULL) {
        pr_err("Error calling alloc(): %s.\n", result);
        return;
    }

    // Fetch the alloc() return value.
    uint64_t alloc_val = 0;
    if ((result = m3_GetResultsV(alloc_func, &alloc_val)) != NULL) {
        pr_err("Error getting results from alloc(): %s.\n", result);
        return;
    }

    // Compute a pointer to the allocated region.
    int32_t *data = (int32_t *)(m3_GetMemory(runtime, NULL, 0) + alloc_val);

    // Fill the allocated array with values.
    for (int i = 0; i < 10; i++) {
        data[i] = i;
    }

    // Call the sum() function.
    if ((result = m3_CallV(sum_func)) != NULL) {
        pr_err("Error calling sum(): %s.\n", result);
        return;
    }

    // Fetch the sum() return value.
    uint64_t sum_val = 0;
    if ((result = m3_GetResultsV(sum_func, &sum_val)) != NULL) {
        pr_err("Error getting results from sum(): %s.\n", result);
        return;
    }

    // Print the sum() return value.
    pr_info("Function returned: %llu.\n", sum_val);
}

static ssize_t
cdev_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
    // Acquire the runtime lock.
    unsigned long flags;
    spin_lock_irqsave(&lock, flags);

    // Free the current runtime if it exists.
    if (runtime != NULL) {
        m3_FreeRuntime(runtime);
        runtime = NULL;
    }

    // Free the current code buffer if it exists.
    if (wasm_code != NULL) {
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
    }

    // Allocate a new code buffer.
    if ((wasm_code = kmalloc(len, GFP_KERNEL)) == NULL) {
        pr_err("Failed to allocate buffer of length %zu bytes.\n", len);
        return -ENOMEM;
    }

    // Copy the code from user space into the buffer.
    if (copy_from_user(wasm_code, buf, len) != 0) {
        kfree(wasm_code);
        wasm_code = NULL;
        pr_err("Failed to copy data from user space.\n");
        return -EFAULT;
    }
    wasm_size = len;

    // Initialize the Wasm3 runtime.
    if ((runtime = m3_NewRuntime(env, WASM_STACK_SIZE, NULL)) == NULL) {
        pr_err("Failed to create Wasm3 runtime.\n");
        return -ENOMEM;
    }

    // Parse the WASM module.
    M3Result result;
    if ((result = m3_ParseModule(env, &module, wasm_code, wasm_size)) != NULL) {
        pr_err("Failed to parse module: %s.\n", result);
        m3_FreeRuntime(runtime);
        runtime = NULL;
        return -EINVAL;
    }

    // Load the WASM module.
    if ((result = m3_LoadModule(runtime, module)) != NULL) {
        pr_err("Failed to load module: %s.\n", result);
        m3_FreeRuntime(runtime);
        runtime = NULL;
        return -ENOMEM;
    }

    // Link the print_int() function to the module.
    if ((result = m3_LinkRawFunction(module, "custom", "print_int", "i(i)", &print_int)) != NULL) {
        pr_err("Failed to link print_int() to module: %s.\n", result);
        m3_FreeRuntime(runtime);
        runtime = NULL;
        return -EINVAL;
    }

    // Find the alloc() WASM function in the module.
    if ((result = m3_FindFunction(&alloc_func, runtime, "alloc")) != NULL) {
        pr_err("Error finding alloc() in module: %s.\n", result);
        m3_FreeRuntime(runtime);
        return -EINVAL;
    }

    // Find the sum() WASM function in the module.
    if ((result = m3_FindFunction(&sum_func, runtime, "sum")) != NULL) {
        pr_err("Error finding sum() in module: %s.\n", result);
        m3_FreeRuntime(runtime);
        return -EINVAL;
    }

    test();

    // Release the runtime lock.
    spin_unlock_irqrestore(&lock, flags);

    return len;
}

/*
 * Called when the kernel module is unloaded.
 */
static void __exit
wasm_cleanup(void)
{
    // Free the Wasm3 runtime if it exists.
    if (runtime != NULL) {
        m3_FreeRuntime(runtime);
    }

    // Free the code buffer if it exists.
    if (wasm_code != NULL) {
        kfree(wasm_code);
    }

    // Free the character device.
    device_destroy(dev_class, dev_num);
    cdev_del(&cdev);
    unregister_chrdev_region(dev_num, 1);
    class_destroy(dev_class);

    // Free the Wasm3 environment.
    m3_FreeEnvironment(env);

    pr_info("Successfully unloaded WASM module.\n");
}

module_init(wasm_init);
module_exit(wasm_cleanup);
MODULE_LICENSE("Dual BSD/GPL");