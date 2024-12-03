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

#include "wasm3.h"
#include "m3_env.h"

// Constants
#define WASM_STACK_SIZE (64 * 1024) // 64 KB stack

// Device variables
static dev_t dev_num;
static struct cdev c_dev;
static struct class *cl;

#define WASM_IOC_MAGIC 'w'
#define WASM_IOC_PROCESS _IO(WASM_IOC_MAGIC, 0)

m3ApiRawFunction(print_int);
int process_wasm_code(void);
static uint8_t *wasm_buffer = NULL;
static size_t wasm_size = 0;
static int my_open(struct inode *i, struct file *f);
static int my_close(struct inode *i, struct file *f);
static ssize_t my_write(struct file *f, const char __user *buf, size_t len, loff_t *off);
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_close,
    .write = my_write,
    .unlocked_ioctl = my_ioctl,
};

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

static void __exit wasm_exit(void) {
    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);
    if (wasm_buffer) {
        kfree(wasm_buffer);
        wasm_buffer = NULL;
        wasm_size = 0;
    }
    printk(KERN_INFO "WASM kernel module unloaded.\n");
}
static int my_open(struct inode *i, struct file *f) {
    printk(KERN_INFO "wasm_device: open()\n");
    return 0;
}

static int my_close(struct inode *i, struct file *f) {
    printk(KERN_INFO "wasm_device: close()\n");
    return 0;
}

static ssize_t my_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    printk(KERN_INFO "wasm_device: write() called with %zu bytes\n", len);
    if (wasm_buffer) {
        kfree(wasm_buffer);
        wasm_buffer = NULL;
        wasm_size = 0;
    }
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

static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    printk(KERN_INFO "wasm_device: ioctl() called with cmd=%u\n", cmd);
    switch (cmd) {
        case WASM_IOC_PROCESS:
            if (wasm_buffer && wasm_size > 0) {
                int ret = process_wasm_code();
                if (ret < 0) {
                    printk(KERN_ERR "Failed to process WASM code\n");
                    return ret;
                }
                printk(KERN_INFO "WASM code processed successfully\n");
                return 0;
            } else {
                printk(KERN_ERR "No WASM code loaded\n");
                return -EINVAL;
            }
            break;
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
int process_wasm_code(void) {
    M3Result result = m3Err_none;
    printk(KERN_INFO "Processing WASM code of size %zu bytes\n", wasm_size);
    IM3Environment env = m3_NewEnvironment();
    if (!env) {
        printk(KERN_ERR "Failed to create Wasm3 environment.\n");
        return -ENOMEM;
    }
    IM3Runtime runtime = m3_NewRuntime(env, WASM_STACK_SIZE, NULL);
    if (!runtime) {
        printk(KERN_ERR "Failed to create Wasm3 runtime.\n");
        m3_FreeEnvironment(env);
        return -ENOMEM;
    }
    IM3Module module;
    result = m3_ParseModule(env, &module, wasm_buffer, wasm_size);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error parsing module: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }
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

    // Find the sum() function in the WASM module
    IM3Function sum_func;
    result = m3_FindFunction(&sum_func, runtime, "sum");
    if (result != m3Err_none) {
        printk(KERN_ERR "Error finding sum function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Call the sum() function
    result = m3_CallV(sum_func);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error calling sum function: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }

    // Get the return value from sum()
    uint32_t sum_result = 0;
    result = m3_GetResultsV(sum_func, &sum_result);
    if (result != m3Err_none) {
        printk(KERN_ERR "Error getting sum result: %s\n", result);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return -EINVAL;
    }
    printk(KERN_INFO "Sum function returned: %u\n", sum_result);
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);

    return 0;
}

module_init(wasm_init);
module_exit(wasm_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to execute WASM code via character device and ioctl");
