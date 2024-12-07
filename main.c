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

#include "wasm3.h"
#include "m3_env.h"

#include "packet.h"

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

// The filter function within the Wasm3 module
IM3Function filter_func = NULL;

// Pointer to packer header on WASM runtime's heap
struct packet_header *header;

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
    // Initialize the Wasm3 environment.
    if ((env = m3_NewEnvironment()) == NULL) {
        pr_err("Failed to create Wasm3 environment.\n");
        return -1;
    }

    // Register the device class.
    if (IS_ERR(dev_class = class_create("wasm"))) {
        pr_err("Failed to register the character device class.\n");
        m3_FreeEnvironment(env);
        return PTR_ERR(dev_class);
    }

    // Register a character device number.
    if (alloc_chrdev_region(&dev_num, 0, 1, "wasm") < 0) {
        pr_err("Failed to allocate a character device number.\n");
        class_destroy(dev_class);
        m3_FreeEnvironment(env);
        return dev_num;
    }

    // Initialize and add the character device.
    cdev_init(&cdev, &fops);
    int ret;
    if ((ret = cdev_add(&cdev, dev_num, 1)) < 0) {
        pr_err("Failed to add the character device.\n");
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        m3_FreeEnvironment(env);
        return ret;
    }

    // Register the device node.
    if (IS_ERR(dev = device_create(dev_class, NULL, dev_num, NULL, "wasm"))) {
        pr_err("Failed to create the character device.\n");
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        m3_FreeEnvironment(env);
        return PTR_ERR(dev);
    }

    // Register the netfilter hook.
    if ((ret = nf_register_net_hook(&init_net, &nfho)) < 0) {
        pr_err("Failed to register the netfilter hook.\n");
        device_destroy(dev_class, dev_num);
        cdev_del(&cdev);
        unregister_chrdev_region(dev_num, 1);
        class_destroy(dev_class);
        m3_FreeEnvironment(env);
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
    spin_lock_irqsave(&lock, flags);

    // Free the current runtime if it exists.
    if (runtime != NULL) {
        alloc_func = NULL;
        filter_func = NULL;
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

    // Initialize the Wasm3 runtime.
    if ((runtime = m3_NewRuntime(env, WASM_STACK_SIZE, NULL)) == NULL) {
        pr_err("Failed to create Wasm3 runtime.\n");
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
        spin_unlock_irqrestore(&lock, flags);
        return -ENOMEM;
    }

    // Parse the WASM module.
    M3Result result;
    if ((result = m3_ParseModule(env, &module, wasm_code, wasm_size)) != NULL) {
        pr_err("Failed to parse module: %s.\n", result);
        m3_FreeRuntime(runtime);
        runtime = NULL;
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
        spin_unlock_irqrestore(&lock, flags);
        return -EINVAL;
    }

    // Load the WASM module.
    if ((result = m3_LoadModule(runtime, module)) != NULL) {
        pr_err("Failed to load module: %s.\n", result);
        m3_FreeRuntime(runtime);
        runtime = NULL;
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
        spin_unlock_irqrestore(&lock, flags);
        return -ENOMEM;
    }

    // Link the print_int() function to the module.
    if ((result = m3_LinkRawFunction(module, "custom", "print_int", "i(i)", &print_int)) != NULL) {
        pr_err("Failed to link print_int() to module: %s.\n", result);
    }

    // Find the alloc() WASM function in the module.`
    if ((result = m3_FindFunction(&alloc_func, runtime, "alloc")) != NULL) {
        pr_err("Error finding alloc() in module: %s.\n", result);
        m3_FreeRuntime(runtime);
        runtime = NULL;
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
        spin_unlock_irqrestore(&lock, flags);
        return -EINVAL;
    }

    // Find the filter() WASM function in the module.
    if ((result = m3_FindFunction(&filter_func, runtime, "filter")) != NULL) {
        pr_err("Error finding filter() in module: %s.\n", result);
        alloc_func = NULL;
        m3_FreeRuntime(runtime);
        runtime = NULL;
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
        spin_unlock_irqrestore(&lock, flags);
        return -EINVAL;
    }

    // Call the alloc() function.
    if ((result = m3_CallV(alloc_func, sizeof(struct packet_header))) != NULL) {
        pr_err("Error calling alloc(): %s.\n", result);
        alloc_func = NULL;
        filter_func = NULL;
        m3_FreeRuntime(runtime);
        runtime = NULL;
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
        spin_unlock_irqrestore(&lock, flags);
        return -EINVAL;
    }

    // Fetch the alloc() return value.
    uint64_t alloc_val = 0;
    if ((result = m3_GetResultsV(alloc_func, &alloc_val)) != NULL) {
        pr_err("Error getting results from alloc(): %s.\n", result);
        alloc_func = NULL;
        filter_func = NULL;
        m3_FreeRuntime(runtime);
        runtime = NULL;
        kfree(wasm_code);
        wasm_code = NULL;
        wasm_size = 0;
        spin_unlock_irqrestore(&lock, flags);
        return -EINVAL;
    }

    // Compute a pointer to the allocated region.
    header = (struct packet_header *)(m3_GetMemory(runtime, NULL, 0) + alloc_val);

    // Release the runtime lock.
    spin_unlock_irqrestore(&lock, flags);

    pr_info("Successfully loaded %zu bytes of WASM code.\n", wasm_size);

    return len;
}

/*
 * Handle an incoming IPv4 packet.
 */
static unsigned int
nf_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // Do nothing if no filter function exists.
    if (filter_func == NULL) {
        return NF_ACCEPT;
    }

    // TODO: use multiple runtimes to avoid serializing packet processing

    // Acquire the runtime lock.
    unsigned long flags;
    spin_lock_irqsave(&lock, flags);

    // Copy a portion of the packet headers into the runtime's memory.
    struct iphdr *ip_h = (struct iphdr *)skb_network_header(skb);
    header->src_ip = ntohl(ip_h->saddr);
    header->dst_ip = ntohl(ip_h->daddr);
    header->len = ntohs(ip_h->tot_len);
    switch (ip_h->protocol) {
        case IPPROTO_TCP:
            header->prot = TCP;
            struct tcphdr *tcp_h = tcp_hdr(skb);
            header->src_pt = ntohs(tcp_h->source);
            header->dst_pt = ntohs(tcp_h->dest);
            break;
        case IPPROTO_UDP:
            header->prot = UDP;
            struct udphdr *udp_h = udp_hdr(skb);
            header->src_pt = ntohs(udp_h->source);
            header->dst_pt = ntohs(udp_h->dest);
            break;
        default:
            spin_unlock_irqrestore(&lock, flags);
            return NF_ACCEPT;
    }

    // Call the filter() function.
    M3Result result;
    if ((result = m3_CallV(filter_func)) != NULL) {
        pr_err("Error calling filter(): %s.\n", result);
        spin_unlock_irqrestore(&lock, flags);
        return NF_ACCEPT;
    }

    // Fetch the filter() return value.
    uint32_t filter_val = 0;
    if ((result = m3_GetResultsV(filter_func, &filter_val)) != NULL) {
        pr_err("Error getting results from filter(): %s.\n", result);
        spin_unlock_irqrestore(&lock, flags);
        return NF_ACCEPT;
    }

    // Release the runtime lock.
    spin_unlock_irqrestore(&lock, flags);

    // The return value specified what should be done with the packet.
    return filter_val;
}

/*
 * Called when the kernel module is unloaded.
 */
static void __exit
wasm_cleanup(void)
{
    // Unregister the netfilter hook.
    nf_unregister_net_hook(&init_net, &nfho);

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