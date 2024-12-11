/*
 * main.c - Offer a character device which executes WASM bytecode to filter IPv4 packets.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "wasm3.h"

#include "packet.h"

#define WASM_STACK_SIZE (64 * 1024) // 64 KB stack

// A runtime and its associated metadata
struct wasm_runtime {
    spinlock_t lock; // The runtime lock
    IM3Environment env; // The Wasm3 environment
    IM3Runtime runtime; // The Wasm3 runtime
    IM3Module module; // The Wasm3 module
    IM3Function alloc_func; // The allocation function within the Wasm3 module
    IM3Function filter_func; // The filter function within the Wasm3 module
    struct iphdr *header; // A pointer to the packer header on WASM runtime's heap
};

// The reconfiguration lock
DEFINE_SPINLOCK(reconf_lock);

// The WASM code buffer
char *wasm_code = NULL;

// The size of the WASM code buffer
unsigned int wasm_size = 0;

// A pointer to the array of Wasm3 runtimes
struct wasm_runtime *runtimes;

// The device number
static dev_t dev_num;

// The device class
static struct class *dev_class;

// The device
static struct device *dev;

// The character device
static struct cdev cdev;

// The character device write handler
static ssize_t cdev_write(struct file *f, const char __user *buf, size_t len, loff_t *off);

// The character device's file operations
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .write = cdev_write,
};

// The netfilter hook packet handler
static unsigned int nf_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// The netfilter hook's operations
static struct nf_hook_ops nfho = {
    .hook = nf_filter,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
};

/*
 * Called by the WASM program to print an integer.
 */
m3ApiRawFunction(print_int)
{
    // Specify the function's signature.
    m3ApiReturnType(int32_t);
    m3ApiGetArg(int32_t, i);

    pr_info("From WASM: %i. [%i]\n", i, smp_processor_id());

    m3ApiReturn(0);
}

/*
 * Called when the kernel module is loaded.
 */
static int __init
wasm_init(void)
{
    // Allocate the array of runtimes.
    if ((runtimes = kcalloc(nr_cpu_ids, sizeof(struct wasm_runtime), GFP_KERNEL)) == NULL) {
        pr_err("Failed to allocate runtime array.\n");
        return -1;
    }

    // Initialize the lock for each runtime.
    for (int cpu = 0; cpu < nr_cpu_ids; cpu++) {
        spin_lock_init(&runtimes[cpu].lock);
    }

    // Register the device class.
    if (IS_ERR(dev_class = class_create("wasm"))) {
        pr_err("Failed to register the character device class.\n");
        kfree(runtimes);
        return PTR_ERR(dev_class);
    }

    // Register a character device number.
    if (alloc_chrdev_region(&dev_num, 0, 1, "wasm") < 0) {
        pr_err("Failed to allocate a character device number.\n");
        class_destroy(dev_class);
        kfree(runtimes);
        return dev_num;
    }

    // Initialize and add the character device.
    cdev_init(&cdev, &fops);
    int ret;
    if ((ret = cdev_add(&cdev, dev_num, 1)) < 0) {
        pr_err("Failed to add the character device.\n");
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        kfree(runtimes);
        return ret;
    }

    // Register the device node.
    if (IS_ERR(dev = device_create(dev_class, NULL, dev_num, NULL, "wasm"))) {
        pr_err("Failed to create the character device.\n");
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        kfree(runtimes);
        return PTR_ERR(dev);
    }

    // Register the netfilter hook.
    if ((ret = nf_register_net_hook(&init_net, &nfho)) < 0) {
        pr_err("Failed to register the netfilter hook.\n");
        device_destroy(dev_class, dev_num);
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        kfree(runtimes);
        return ret;
    }

    pr_info("Successfully loaded WASM module.\n");

    return 0;
}

/*
 * Clean up after a failed reconfiguration attempt.
 */
static void
reconfigure_abort(int fail_cpu, char *new_wasm_code, struct wasm_runtime *new_runtimes)
{
    // Free every new runtime and environment that has been created up to this point.
    for (int cpu = 0; cpu <= fail_cpu; cpu++) {
        if (new_runtimes[cpu].runtime != NULL) {
            m3_FreeRuntime(new_runtimes[cpu].runtime);
        }
        if (new_runtimes[cpu].env != NULL) {
            m3_FreeEnvironment(new_runtimes[cpu].env);
        }
    }

    // Free the temporary array of new runtimes.
    kfree(new_runtimes);

    // Free the new code buffer.
    kfree(new_wasm_code);
}

/*
 * Handle a write to the character device (i.e., a reconfiguration attempt).
 */
static ssize_t
cdev_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
    // Acquire the reconfiguration lock.
    unsigned long reconf_flags;
    spin_lock_irqsave(&reconf_lock, reconf_flags);

    // Allocate a new code buffer.
    char *new_wasm_code;
    if ((new_wasm_code = kmalloc(len, GFP_KERNEL)) == NULL) {
        pr_err("Failed to allocate code buffer of length %zu bytes.\n", len);
        spin_unlock_irqrestore(&reconf_lock, reconf_flags);
        return -ENOMEM;
    }

    // Copy the code from user space into the buffer.
    if (copy_from_user(new_wasm_code, buf, len) != 0) {
        pr_err("Failed to copy code from user space.\n");
        kfree(new_wasm_code);
        spin_unlock_irqrestore(&reconf_lock, reconf_flags);
        return -EFAULT;
    }

    // Allocate a temporary array to store the new runtimes.
    struct wasm_runtime *new_runtimes;  
    if ((new_runtimes = kcalloc(nr_cpu_ids, sizeof(struct wasm_runtime), GFP_KERNEL)) == NULL) {
        pr_err("Failed to allocate new runtime array.\n");
        kfree(new_wasm_code);
        spin_unlock_irqrestore(&reconf_lock, reconf_flags);
        return -ENOMEM;
    }

    // Set up all of the new runtimes.
    for (int cpu = 0; cpu < nr_cpu_ids; cpu++) {
        // Initialize the environment.
        if ((new_runtimes[cpu].env = m3_NewEnvironment()) == NULL) {
            pr_err("Failed to create environment. [%i]\n", cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -ENOMEM;
        }

        // Initialize the runtime.
        if ((new_runtimes[cpu].runtime = m3_NewRuntime(new_runtimes[cpu].env, WASM_STACK_SIZE, NULL)) == NULL) {
            pr_err("Failed to create new runtime. [%i]\n", cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -ENOMEM;
        }

        // Parse the WASM module.
        M3Result result;
        if ((result = m3_ParseModule(new_runtimes[cpu].env, &new_runtimes[cpu].module, new_wasm_code, len)) != NULL) {
            pr_err("Failed to parse module: %s. [%i]\n", result, cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -EINVAL;
        }

        // Load the WASM module.
        if ((result = m3_LoadModule(new_runtimes[cpu].runtime, new_runtimes[cpu].module)) != NULL) {
            pr_err("Failed to load module: %s. [%i]\n", result, cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -ENOMEM;
        }

        // Link the print_int() function to the module.
        if ((result = m3_LinkRawFunction(new_runtimes[cpu].module, "custom", "print_int", "i(i)", &print_int)) != NULL) {
            pr_info("Failed to link print_int() to module: %s. [%i]\n", result, cpu);
        }

        // Find the alloc() WASM function in the module.`
        if ((result = m3_FindFunction(&new_runtimes[cpu].alloc_func, new_runtimes[cpu].runtime, "alloc")) != NULL) {
            pr_err("Error finding alloc() in module: %s.\n [%i]", result, cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -EINVAL;
        }

        // Find the filter() WASM function in the module.
        if ((result = m3_FindFunction(&new_runtimes[cpu].filter_func, new_runtimes[cpu].runtime, "filter")) != NULL) {
            pr_err("Error finding filter() in module: %s. [%i]\n", result, cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -EINVAL;
        }

        // Call the alloc() function.
        if ((result = m3_CallV(new_runtimes[cpu].alloc_func, sizeof(struct iphdr))) != NULL) {
            pr_err("Error calling alloc(): %s. [%i]\n", result, cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -EINVAL;
        }

        // Fetch the alloc() return value.
        uint64_t alloc_val = 0;
        if ((result = m3_GetResultsV(new_runtimes[cpu].alloc_func, &alloc_val)) != NULL) {
            pr_err("Error getting results from alloc(): %s. [%i]\n", result, cpu);
            reconfigure_abort(cpu, new_wasm_code, new_runtimes);
            spin_unlock_irqrestore(&reconf_lock, reconf_flags);
            return -EINVAL;
        }

        // Compute a pointer to the allocated region.
        new_runtimes[cpu].header = (struct iphdr *)(m3_GetMemory(new_runtimes[cpu].runtime, NULL, 0) + alloc_val);
    }

    // Install all of the new runtimes.
    for (int cpu = 0; cpu < nr_cpu_ids; cpu++) {
        // Acquire the runtime lock.
        unsigned long runtime_flags;
        spin_lock_irqsave(&runtimes[cpu].lock, runtime_flags);

        // Free the current runtime if it exists.
        if (runtimes[cpu].runtime != NULL) {
            m3_FreeRuntime(runtimes[cpu].runtime);
        }

        // Free the current environment if it exists.
        if (runtimes[cpu].env != NULL) {
            m3_FreeEnvironment(runtimes[cpu].env);
        }

        // Copy the new pointers into the actual runtime array.
        runtimes[cpu].env = new_runtimes[cpu].env;
        runtimes[cpu].runtime = new_runtimes[cpu].runtime;
        runtimes[cpu].module = new_runtimes[cpu].module;
        runtimes[cpu].alloc_func = new_runtimes[cpu].alloc_func;
        runtimes[cpu].filter_func = new_runtimes[cpu].filter_func;
        runtimes[cpu].header = new_runtimes[cpu].header;

        // Release the runtime lock.
        spin_unlock_irqrestore(&runtimes[cpu].lock, runtime_flags);
    }

    // Free the temporary array of new runtimes.
    kfree(new_runtimes);

    // Free the old code buffer if it exists.
    if (wasm_code != NULL) {
        kfree(wasm_code);
    }

    // Save the new code buffer.
    wasm_code = new_wasm_code;
    wasm_size = len;

    // Release the reconfiguration lock.
    spin_unlock_irqrestore(&reconf_lock, reconf_flags);

    pr_info("Successfully loaded %zu bytes of WASM code.\n", wasm_size);

    return len;
}

/*
 * Handle an incoming IPv4 packet.
 */
static unsigned int
nf_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Disable preemption and get the ID of the current CPU.
    int cpu = get_cpu();

    // Acquire the runtime lock.
    unsigned long runtime_flags;
    spin_lock_irqsave(&runtimes[cpu].lock, runtime_flags);

    // Do nothing if no runtime exists.
    if (runtimes[cpu].runtime == NULL) {
        spin_unlock_irqrestore(&runtimes[cpu].lock, runtime_flags);
        put_cpu();
        return NF_ACCEPT;
    }

    // Copy the packet's IP header into the runtime's memory.
    if (skb_copy_bits(skb, skb_network_offset(skb), runtimes[cpu].header, sizeof(struct iphdr)) < 0) {
        pr_err("Error copying IP header into packet.\n");
        spin_unlock_irqrestore(&runtimes[cpu].lock, runtime_flags);
        put_cpu();
        return NF_ACCEPT;
    }

    // Call the filter() function.
    M3Result result;
    if ((result = m3_CallV(runtimes[cpu].filter_func)) != NULL) {
        pr_err("Error calling filter(): %s. [%i]\n", result, cpu);
        spin_unlock_irqrestore(&runtimes[cpu].lock, runtime_flags);
        put_cpu();
        return NF_ACCEPT;
    }

    // Fetch the filter() return value.
    uint32_t filter_val = 0;
    if ((result = m3_GetResultsV(runtimes[cpu].filter_func, &filter_val)) != NULL) {
        pr_err("Error getting results from filter(): %s. [%i]\n", result, cpu);
        spin_unlock_irqrestore(&runtimes[cpu].lock, runtime_flags);
        put_cpu();
        return NF_ACCEPT;
    }

    // If filter() returned true, copy the IP header back into the original packet and recompute its checksum.
    if (filter_val) {
        memcpy(skb_network_header(skb), runtimes[cpu].header, sizeof(ip_hdr));
        ip_send_check((struct iphdr *)skb_network_header(skb));
    }

    // Release the runtime lock.
    spin_unlock_irqrestore(&runtimes[cpu].lock, runtime_flags);

    // Enable preemption.
    put_cpu();

    // The return value specifies what should be done with the packet.
    return filter_val;
}

/*
 * Called when the kernel module is unloaded.
 */
static void __exit
wasm_cleanup(void)
{
    // Free the character device.
    device_destroy(dev_class, dev_num);
    cdev_del(&cdev);
    unregister_chrdev_region(dev_num, 1);
    class_destroy(dev_class);

    // Unregister the netfilter hook.
    nf_unregister_net_hook(&init_net, &nfho);

    // At this point, all concurrent handlers should be finished executing.

    // Free all of the Wasm3 runtimes.
    for (int cpu = 0; cpu < nr_cpu_ids; cpu++) {
        // Free the runtime if it exists.
        if (runtimes[cpu].runtime != NULL) {
            m3_FreeRuntime(runtimes[cpu].runtime);
        }

        // Free the environment if it exists.
        if (runtimes[cpu].env != NULL) {
            m3_FreeEnvironment(runtimes[cpu].env);
        }
    }

    // Free the code buffer if it exists.
    if (wasm_code != NULL) {
        kfree(wasm_code);
    }

    // Free the array of runtimes.
    kfree(runtimes);
    
    pr_info("Successfully unloaded WASM module.\n");
}

module_init(wasm_init);
module_exit(wasm_cleanup);
MODULE_LICENSE("Dual BSD/GPL");