/*
 * main.c - Offer a character device which executes WASM bytecode to filter IPv4 packets.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/cpumask.h>

#include "wasm3.h"
#include "m3_env.h"

#include "packet.h"

#define WASM_STACK_SIZE (64 * 1024) // 64 KB stack

struct core_info {
    IM3Environment env;
    IM3Runtime runtime;
    IM3Module module;
    IM3Function alloc_func;
    IM3Function filter_func;
    struct packet_header *header;
};

struct core_info *core_infos = NULL;


// The Wasm3 runtime lock
DEFINE_SPINLOCK(lock);

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

// File operations
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .write = cdev_write,
};

// WASM code buffer
char *wasm_code = NULL;

// Size of WASM code buffer
unsigned int wasm_size = 0;

// Netfilter hook packet handler
static unsigned int nf_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// Netfilter hook operations
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

    pr_info("From WASM: %i\n", i);

    m3ApiReturn(0);
}

/*
 * Called when the kernel module is loaded.
 */
static int __init
wasm_init(void)
{
    int i;
    M3Result result;

    // Determine the number of cores available on the machine
    int num_cores = num_online_cpus();

    // Allocate memory for core_infos
    core_infos = kmalloc_array(num_cores, sizeof(struct core_info), GFP_KERNEL);
    if (!core_infos) {
        pr_err("Failed to allocate memory for core_infos.\n");
        return -ENOMEM;
    }

    // Initialize the Wasm3 environment for each core.
    for (i = 0; i < num_cores; i++) {
        struct core_info *info = &core_infos[i];

        if ((info->env = m3_NewEnvironment()) == NULL) {
            pr_err("Failed to create Wasm3 environment for core %d.\n", i);
            kfree(core_infos);
            return -ENOMEM;
        }

        // Initialize the Wasm3 runtime.
        if ((info->runtime = m3_NewRuntime(info->env, WASM_STACK_SIZE, NULL)) == NULL) {
            pr_err("Failed to create Wasm3 runtime for core %d.\n", i);
            m3_FreeEnvironment(info->env);
            kfree(core_infos);
            return -ENOMEM;
        }
    }

    // Register the device class.
    if (IS_ERR(dev_class = class_create("wasm"))) {
        pr_err("Failed to register the character device class.\n");
        for (i = 0; i < num_cores; i++) {
            struct core_info *info = &core_infos[i];
            m3_FreeRuntime(info->runtime);
            m3_FreeEnvironment(info->env);
        }
        kfree(core_infos);
        return PTR_ERR(dev_class);
    }

    // Register a character device number.
    if (alloc_chrdev_region(&dev_num, 0, 1, "wasm") < 0) {
        pr_err("Failed to allocate a character device number.\n");
        class_destroy(dev_class);
        for (i = 0; i < num_cores; i++) {
            struct core_info *info = &core_infos[i];
            m3_FreeRuntime(info->runtime);
            m3_FreeEnvironment(info->env);
        }
        kfree(core_infos);
        return dev_num;
    }

    // Initialize and add the character device.
    cdev_init(&cdev, &fops);
    int ret;
    if ((ret = cdev_add(&cdev, dev_num, 1)) < 0) {
        pr_err("Failed to add the character device.\n");
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        for (i = 0; i < num_cores; i++) {
            struct core_info *info = &core_infos[i];
            m3_FreeRuntime(info->runtime);
            m3_FreeEnvironment(info->env);
        }
        kfree(core_infos);
        return ret;
    }

    // Register the device node.
    if (IS_ERR(dev = device_create(dev_class, NULL, dev_num, NULL, "wasm"))) {
        pr_err("Failed to create the character device.\n");
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        for (i = 0; i < num_cores; i++) {
            struct core_info *info = &core_infos[i];
            m3_FreeRuntime(info->runtime);
            m3_FreeEnvironment(info->env);
        }
        kfree(core_infos);
        return PTR_ERR(dev);
    }

    // Register the netfilter hook.
    if ((ret = nf_register_net_hook(&init_net, &nfho)) < 0) {
        pr_err("Failed to register the netfilter hook.\n");
        device_destroy(dev_class, dev_num);
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        for (i = 0; i < num_cores; i++) {
            struct core_info *info = &core_infos[i];
            m3_FreeRuntime(info->runtime);
            m3_FreeEnvironment(info->env);
        }
        kfree(core_infos);
        return ret;
    }

    pr_info("Successfully loaded WASM module.\n");

    return 0;
}

/*
 * Handle a write to the character device.
 */
static ssize_t
cdev_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
    // Acquire the runtime lock.
    unsigned long flags;
    M3Result result;
    int i;

    spin_lock_irqsave(&lock, flags);

    // Free the current code buffer if it exists.
    if (wasm_code != NULL) {
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
    }

    // Allocate a new code buffer.
    if ((wasm_code = kmalloc(len, GFP_KERNEL)) == NULL) {
        pr_err("Failed to allocate buffer of length %zu bytes.\n", len);
        spin_unlock_irqrestore(&lock, flags);
        return -ENOMEM;
    }

    // Copy the code from user space into the buffer.
    if (copy_from_user(wasm_code, buf, len) != 0) {
        pr_err("Failed to copy data from user space.\n");
        kfree(wasm_code);
        wasm_code = NULL;
        spin_unlock_irqrestore(&lock, flags);
        return -EFAULT;
    }
    wasm_size = len;

    // Initialize the Wasm3 runtime for each core.
    for (i = 0; i < num_online_cpus(); i++) {
        struct core_info *info = &core_infos[i];

        // Parse the WASM module.
        if ((result = m3_ParseModule(info->env, &info->module, wasm_code, wasm_size)) != NULL) {
            pr_err("Failed to parse module for core %d: %s.\n", i, result);
            m3_FreeRuntime(info->runtime);
            info->runtime = NULL;
            spin_unlock_irqrestore(&lock, flags);
            return -EINVAL;
        }

        // Load the WASM module.
        if ((result = m3_LoadModule(info->runtime, info->module)) != NULL) {
            pr_err("Failed to load module for core %d: %s.\n", i, result);
            m3_FreeRuntime(info->runtime);
            info->runtime = NULL;
            spin_unlock_irqrestore(&lock, flags);
            return -ENOMEM;
        }

        // Link the print_int() function to the module.
        if ((result = m3_LinkRawFunction(info->module, "custom", "print_int", "i(i)", &print_int)) != NULL) {
            pr_err("Failed to link print_int() to module for core %d: %s.\n", i, result);
        }

        // Find the alloc() WASM function in the module.
        if ((result = m3_FindFunction(&info->alloc_func, info->runtime, "alloc")) != NULL) {
            pr_err("Error finding alloc() in module for core %d: %s.\n", i, result);
            m3_FreeRuntime(info->runtime);
            info->runtime = NULL;
            spin_unlock_irqrestore(&lock, flags);
            return -EINVAL;
        }

        // Find the filter() WASM function in the module.
        if ((result = m3_FindFunction(&info->filter_func, info->runtime, "filter")) != NULL) {
            pr_err("Error finding filter() in module for core %d: %s.\n", i, result);
            info->alloc_func = NULL;
            m3_FreeRuntime(info->runtime);
            info->runtime = NULL;
            spin_unlock_irqrestore(&lock, flags);
            return -EINVAL;
        }

        // Call the alloc() function.
        if ((result = m3_CallV(info->alloc_func, sizeof(struct packet_header))) != NULL) {
            pr_err("Error calling alloc() in module for core %d: %s.\n", i, result);
            info->alloc_func = NULL;
            info->filter_func = NULL;
            m3_FreeRuntime(info->runtime);
            info->runtime = NULL;
            spin_unlock_irqrestore(&lock, flags);
            return -EINVAL;
        }

        // Fetch the alloc() return value.
        uint64_t alloc_val = 0;
        if ((result = m3_GetResultsV(info->alloc_func, &alloc_val)) != NULL) {
            pr_err("Error getting results from alloc() in module for core %d: %s.\n", i, result);
            info->alloc_func = NULL;
            info->filter_func = NULL;
            m3_FreeRuntime(info->runtime);
            info->runtime = NULL;
            spin_unlock_irqrestore(&lock, flags);
            return -EINVAL;
        }

        // Compute a pointer to the allocated region.
        info->header = (struct packet_header *)(m3_GetMemory(info->runtime, NULL, 0) + alloc_val);
    }

    // Release the runtime lock.
    spin_unlock_irqrestore(&lock, flags);

    return len;
}

/*
 * Handle an incoming IPv4 packet.
 */
static unsigned int nf_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Get the current CPU.
    int cpu = get_cpu();
    struct core_info *info = &core_infos[cpu];

    // Do nothing if no filter function exists.
    if (info->filter_func == NULL) {
        put_cpu();
        return NF_ACCEPT;
    }

    // Acquire the runtime lock.
    unsigned long flags;
    spin_lock_irqsave(&lock, flags);

    // Copy a portion of the packet headers into the runtime's memory.
    struct iphdr *ip_h = (struct iphdr *)skb_network_header(skb);
    info->header->src_ip = ntohl(ip_h->saddr);
    info->header->dst_ip = ntohl(ip_h->daddr);
    info->header->len = ntohs(ip_h->tot_len);
    switch (ip_h->protocol) {
        case IPPROTO_TCP:
            info->header->prot = TCP;
            struct tcphdr *tcp_h = tcp_hdr(skb);
            info->header->src_pt = ntohs(tcp_h->source);
            info->header->dst_pt = ntohs(tcp_h->dest);
            break;
        case IPPROTO_UDP:
            info->header->prot = UDP;
            struct udphdr *udp_h = udp_hdr(skb);
            info->header->src_pt = ntohs(udp_h->source);
            info->header->dst_pt = ntohs(udp_h->dest);
            break;
        default:
            spin_unlock_irqrestore(&lock, flags);
            put_cpu();
            return NF_ACCEPT;
    }

    // Call the filter() function.
    M3Result result;
    if ((result = m3_CallV(info->filter_func)) != NULL) {
        pr_err("Error calling filter() on CPU %d: %s.\n", cpu, result);
        spin_unlock_irqrestore(&lock, flags);
        put_cpu();
        return NF_ACCEPT;
    }

    // Fetch the filter() return value.
    uint32_t filter_val = 0;
    if ((result = m3_GetResultsV(info->filter_func, &filter_val)) != NULL) {
        pr_err("Error getting results from filter() on CPU %d: %s.\n", cpu, result);
        spin_unlock_irqrestore(&lock, flags);
        put_cpu();
        return NF_ACCEPT;
    }

    // Release the runtime lock.
    spin_unlock_irqrestore(&lock, flags);
    put_cpu();

    // The return value specifies what should be done with the packet.
    return filter_val;
}

/*
 * Called when the kernel module is unloaded.
 */
static void __exit wasm_cleanup(void)
{
    int i;
    int num_cores = num_online_cpus();

    // Unregister the netfilter hook.
    nf_unregister_net_hook(&init_net, &nfho);

    // Free the Wasm3 runtime and environment for each core.
    if (core_infos != NULL) {
        for (i = 0; i < num_cores; i++) {
            struct core_info *info = &core_infos[i];

            if (info->runtime != NULL) {
                m3_FreeRuntime(info->runtime);
            }

            if (info->env != NULL) {
                m3_FreeEnvironment(info->env);
            }
        }

        // Free the core_infos array.
        kfree(core_infos);
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

    pr_info("Successfully unloaded WASM module.\n");
}

module_init(wasm_init);
module_exit(wasm_cleanup);
MODULE_LICENSE("Dual BSD/GPL");