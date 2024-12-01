/*
 * main.c - Test out kernel space WASM.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>

#include "wasm3.h"
#include "m3_env.h"

#define WASM_STACK_SIZE 64 * 1024 // 64 KB stack
#define PROC_NAME "net_trace_stats"
#define DROP_PORT 20080

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

static atomic_t packet_count = ATOMIC_INIT(0);
static struct proc_dir_entry *proc_file;
IM3Runtime runtime;
IM3Environment env;

static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;

  if (!skb)
    return NF_ACCEPT;

  iph = ip_hdr(skb);
  if (!iph)
    return NF_ACCEPT;

  if (iph->protocol == IPPROTO_TCP) {
    tcph = tcp_hdr(skb);
    if (!tcph)
      return NF_ACCEPT;

    if (ntohs(tcph->dest) == DROP_PORT) {
      atomic_inc(&packet_count);
      return NF_DROP; // Drop the packet
    }
  }

  return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = hook_func,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
};

static int proc_show(struct seq_file *m, void *v) {
  seq_printf(m, "Packets dropped: %d\n", atomic_read(&packet_count));
  return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
  return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * Called when the kernel module is loaded.
 */
int
init_module(void)
{
    // Initialize the Wasm3 environment.
    env = m3_NewEnvironment();
    if (!env) {
        pr_err("Failed to create Wasm3 environment.\n");
        return (-1);
    }

    // Initialize the Wasm3 runtime.
    runtime = m3_NewRuntime(env, WASM_STACK_SIZE, NULL);
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

    int ret;

    proc_file = proc_create(PROC_NAME, 0444, NULL, &proc_fops);
    if (!proc_file) {
        pr_err("Failed to create proc entry\n");
        return -ENOMEM;
    }

    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret < 0) {
        pr_err("Failed to register netfilter hook\n");
        remove_proc_entry(PROC_NAME, NULL);
        return ret;
    }

    pr_info("Network trace func loaded\n");

    // Link the print_int() function to the module.
    // m3_LinkRawFunction(module, "custom", "print_int", "i(i)", &print_int);

    // Find the alloc() WASM function.
    // IM3Function alloc_func;
    // result = m3_FindFunction(&alloc_func, runtime, "alloc");
    // if (result) {
    //     pr_err("Error finding function: %s\n", result);
    //     m3_FreeRuntime(runtime);
    //     m3_FreeEnvironment(env);
    //     return (-1);
    // }

    // Call the alloc() function.
    // result = m3_CallV(alloc_func, 10 * sizeof(int32_t));
    // if (result) {
    //     pr_err("Error calling function: %s\n", result);
    //     m3_FreeRuntime(runtime);
    //     m3_FreeEnvironment(env);
    //     return (-1);
    // }

    // // Fetch the alloc() return value.
    // uint64_t alloc_value = 0;
    // result = m3_GetResultsV(alloc_func, &alloc_value);
    // if (result) {
    //     pr_err("Error getting results: %s\n", result);
    //     m3_FreeRuntime(runtime);
    //     m3_FreeEnvironment(env);
    //     return (-1);
    // }

    // Compute a pointer to the allocated region.
    // int32_t *data = (int32_t *)(m3_GetMemory(runtime, NULL, 0) + alloc_value);

    // // Fill the allocated array with values.
    // for (int i = 0; i < 10; i++) {
    //     data[i] = i;
    // }

    // Find the sum() WASM function.
    // IM3Function sum_func;
    // result = m3_FindFunction(&sum_func, runtime, "sum");
    // if (result) {
    //     pr_err("Error finding function: %s\n", result);
    //     m3_FreeRuntime(runtime);
    //     m3_FreeEnvironment(env);
    //     return (-1);
    // }

    // // Call the sum() function.
    // result = m3_CallV(sum_func);
    // if (result) {
    //     pr_err("Error calling function: %s\n", result);
    //     m3_FreeRuntime(runtime);
    //     m3_FreeEnvironment(env);
    //     return (-1);
    // }

    // Fetch the sum() return value.
    // uint64_t sum_value = 0;
    // result = m3_GetResultsV(sum_func, &sum_value);
    // if (result) {
    //     pr_err("Error getting results: %s\n", result);
    //     m3_FreeRuntime(runtime);
    //     m3_FreeEnvironment(env);
    //     return (-1);
    // }

    // Print the sum() return value.
    // pr_info("Function returned: %lu\n", sum_value);

    // Clean up by freeing the runtime and environment.
    // m3_FreeRuntime(runtime);
    // m3_FreeEnvironment(env);

    return (0);
}

/*
 * Called when the kernel module is unloaded.
 */
void
cleanup_module(void)
{
    // Just print a goodbye message for now.
    remove_proc_entry(PROC_NAME, NULL);
    nf_unregister_net_hook(&init_net, &nfho);

    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);

    pr_info("Network trace module unloaded\n");
    pr_info("Goodbye!\n");
}

MODULE_LICENSE("Dual BSD/GPL");