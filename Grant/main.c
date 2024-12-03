// main.c

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ioctl.h>

// Include Wasm3 headers
#include "wasm3.h"
#include "m3_env.h"

// Constants
#define WASM_STACK_SIZE (64 * 1024) // 64 KB stack

// IOCTL commands
#define WASM_IOC_MAGIC 'w'
#define WASM_IOC_SET_DATA _IOW(WASM_IOC_MAGIC, 1, struct wasm_data)
#define WASM_IOC_PROCESS_SUM _IO(WASM_IOC_MAGIC, 0)
#define WASM_IOC_PROCESS_TEST _IO(WASM_IOC_MAGIC, 1)

// Structure to hold data sent from user space
struct wasm_data {
    uint32_t size;
    int32_t array[10]; // Adjust the size as needed
};

// Device variables
static dev_t dev_num;          // Device number
static struct cdev c_dev;      // Character device structure
static struct class *cl;       // Device class

// Buffer to store the WASM code received via write()
static uint8_t *wasm_buffer = NULL;
static size_t wasm_size = 0;

// Buffer to store the data received via ioctl()
static struct wasm_data received_data;

// Function prototypes
static int my_open(struct inode *i, struct file *f);
static int my_close(struct inode *i, struct file *f);
static ssize_t my_write(struct file *f, const char __user *buf, size_t len, loff_t *off);
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
static int process_wasm_code(const char *function_name); // Function prototype

// Function prototype for the imported function from WASM
m3ApiRawFunction(print_int);

// File operations structure
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_close,
    .write = my_write,
    .unlocked_ioctl = my_ioctl,
};

// Module initialization function
static int __init wasm_init(void) {
    int ret;
    struct device *dev_ret;

    printk(KERN_INFO "Initializing WASM kernel module.\n");

    // Register character device region
    if ((ret = alloc_chrdev_region(&dev_num, 0, 1, "wasm_device")) < 0) {
        printk(KERN_ERR "Failed to allocate character device region\n");
        return ret;
    }

    // Create device class
    if (IS_ERR(cl = class_create(THIS_MODULE, "wasm_class"))) {
        unregister_chrdev_region(dev_num, 1);
        printk(KERN_ERR "Failed to create device class\n");
        return PTR_ERR(cl);
    }

    // Create device file
    if (IS_ERR(dev_ret = device_create(cl, NULL, dev_num, NULL, "wasm_device"))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        printk(KERN_ERR "Failed to create device\n");
        return PTR_ERR(dev_ret);
    }

    // Initialize and add the character device
    cdev_init(&c_dev, &fops);
    if ((ret = cdev_add(&c_dev, dev_num, 1)) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        printk(KERN_ERR "Failed to add cdev\n");
        return ret;
    }

    printk(KERN_INFO "WASM device registered successfully.\n");

    return 0;
}

// Module exit function
static void __exit wasm_exit(void) {
    // Clean up character device
    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    // Free the WASM buffer if allocated
    if (wasm_buffer) {
        kfree(wasm_buffer);
        wasm_buffer = NULL;
        wasm_size = 0;
    }

    printk(KERN_INFO "WASM kernel module unloaded.\n");
}

// File operations: open
static int my_open(struct inode *i, struct file *f) {
    printk(KERN_INFO "wasm_device: open()\n");
    return 0;
}

// File operations: close
static int my_close(struct inode *i, struct file *f) {
    printk(KERN_INFO "wasm_device: close()\n");
    return 0;
}

// File operations: write
static ssize_t my_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    printk(KERN_INFO "wasm_device: write() called with %zu bytes\n", len);

    // Free any previously stored WASM buffer
    if (wasm_buffer) {
        kfree(wasm_buffer);
        wasm_buffer = NULL;
        wasm_size = 0;
    }

    // Allocate memory for the incoming WASM code
    wasm_buffer = kmalloc(len, GFP_KERNEL);
    if (!wasm_buffer) {
        printk(KERN_ERR "Failed to allocate memory for wasm_buffer\n");
        return -ENOMEM;
    }

    // Copy data from user space
    if (copy_from_user(wasm_buffer, buf, len)) {
        printk(KERN_ERR "Failed to copy data from user space\n");
        kfree(wasm_buffer);
        wasm_buffer = NULL;
        wasm_size = 0;
        return -EFAULT;
    }

    wasm_size = len;

    printk(KERN_INFO "Received WASM code from user space\n");

    return len;
}

// File operations: ioctl
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    printk(KERN_INFO "wasm_device: ioctl() called with cmd=%u\n", cmd);

    switch (cmd) {
        case WASM_IOC_SET_DATA:
            // Receive data from user space
            if (copy_from_user(&received_data, (void __user *)arg, sizeof(struct wasm_data))) {
                printk(KERN_ERR "Failed to copy data from user space\n");
                return -EFAULT;
            }
            printk(KERN_INFO "Received data of size %u\n", received_data.size);
            return 0;

        case WASM_IOC_PROCESS_SUM:
            // Trigger processing of the sum function
            if (wasm_buffer && wasm_size > 0) {
                printk(KERN_INFO "Starting WASM sum processing\n");
                int ret = process_wasm_code("sum");
                if (ret < 0) {
                    printk(KERN_ERR "Failed to process WASM code with error: %d\n", ret);
                    return ret;
                }
                printk(KERN_INFO "WASM sum processed successfully\n");
                return 0;
            } else {
                printk(KERN_ERR "No WASM code loaded\n");
                return -EINVAL;
            }

        case WASM_IOC_PROCESS_TEST:
            // Trigger processing of the test function
            if (wasm_buffer && wasm_size > 0) {
                printk(KERN_INFO "Starting WASM test processing\n");
                int ret = process_wasm_code("sum"); // Still calling "sum" as both modules export "sum"
                if (ret < 0) {
                    printk(KERN_ERR "Failed to process WASM code with error: %d\n", ret);
                    return ret;
                }
                printk(KERN_INFO "WASM test processed successfully\n");
                return 0;
            } else {
                printk(KERN_ERR "No WASM code loaded\n");
                return -EINVAL;
            }

        default:
            printk(KERN_ERR "Invalid ioctl command\n");
            return -ENOTTY;
    }

    return 0;
}

// The imported print_int function implementation
m3ApiRawFunction(print_int) {
    m3ApiGetArg(int32_t, x);

    printk(KERN_INFO "From WASM: %d\n", x);

    m3ApiSuccess();
}

// Function to process and execute the WASM code
int process_wasm_code(const char *function_name) {
    M3Result result = m3Err_none;

    printk(KERN_INFO "Processing WASM code of size %zu bytes\n", wasm_size);

    // Create the Wasm3 environment
    IM3Environment env = m3_NewEnvironment();
    if (!env) {
        printk(KERN_ERR "Failed to create Wasm3 environment.\n");
        return -ENOMEM;
    }

    // Create the Wasm3 runtime
    IM3Runtime runtime = m3_NewRuntime(env, WASM_STACK_SIZE, NULL);
    if (!runtime) {
        printk(KERN_ERR "Failed to create Wasm3 runtime.\n");
        m3_FreeEnvironment(env);
        return -ENOMEM;
    }

    // Parse the WASM module
    IM3Module module;
    result = m3_ParseModule(env, &module, wasm_buffer, wasm_size);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error parsing module: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Load the WASM module
    result = m3_LoadModule(runtime, module);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error loading module: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Link the print_int() function to the module
    result = m3_LinkRawFunction(module, "custom", "print_int", "v(i)", &print_int);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error linking function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Find the alloc() function in the WASM module
    IM3Function alloc_func;
    result = m3_FindFunction(&alloc_func, runtime, "alloc");
    if (result != m3Err_none) {
        printk(KERN_ERR "Error finding alloc function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Call the alloc() function to allocate memory for the array
    result = m3_CallV(alloc_func, 10 * sizeof(int32_t)); // Allocate space for 10 integers
    if (result != m3Err_none) {
        printk(KERN_ERR "Error calling alloc function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Get the allocated memory address
    uint32_t array_ptr = 0;
    result = m3_GetResultsV(alloc_func, &array_ptr);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error getting alloc result: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    printk(KERN_INFO "Allocated memory at WASM address: %u\n", array_ptr);

    // Get a pointer to the WASM memory
    uint8_t *memory = m3_GetMemory(runtime, NULL, 0);
    if (!memory) {
        printk(KERN_ERR "Failed to get WASM memory\n");
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Copy the received data into WASM memory
    memcpy(memory + array_ptr, received_data.array, received_data.size * sizeof(int32_t));
    printk(KERN_INFO "Copied array data to WASM memory\n");

    // Find the function to execute (sum or test)
    IM3Function target_func;
    result = m3_FindFunction(&target_func, runtime, function_name);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error finding %s function: %s\n", function_name, result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    printk(KERN_INFO "Found %s function. Preparing to call %s(array_ptr=%u, size=%u)\n", function_name, function_name, array_ptr, received_data.size);

    if (strcmp(function_name, "sum") == 0) {
        // Call the sum() function with the array pointer and size
        result = m3_CallV(target_func, array_ptr, received_data.size);
        if (result != m3Err_none) {
            printk(KERN_ERR "Error calling sum function: %s\n", result);
            m3_FreeRuntime(runtime);
            m3_FreeEnvironment(env);
            return -EINVAL;
        }

        // Get the return value from sum()
        uint32_t sum_result = 0;
        result = m3_GetResultsV(target_func, &sum_result);
        if (result != m3Err_none) {
            printk(KERN_ERR "Error getting sum result: %s\n", result);
            m3_FreeRuntime(runtime);
            m3_FreeEnvironment(env);
            return -EINVAL;
        }

        printk(KERN_INFO "Sum function returned: %u\n", sum_result);
    } else if (strcmp(function_name, "sum") == 0) {
        // For 'test' function, which also uses 'sum' name but behaves differently
        // This is a bit of a workaround; alternatively, rename function exports to avoid confusion
        // Here, since both modules export 'sum', handle accordingly
        result = m3_CallV(target_func);
        if (result != m3Err_none) {
            printk(KERN_ERR "Error calling test function: %s\n", result);
            m3_FreeRuntime(runtime);
            m3_FreeEnvironment(env);
            return -EINVAL;
        }
        printk(KERN_INFO "Test function executed successfully.\n");
    } else {
        printk(KERN_ERR "Unknown function name: %s\n", function_name);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Clean up
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);

    return 0;
}

module_init(wasm_init);
module_exit(wasm_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to execute WASM code via character device and ioctl");
