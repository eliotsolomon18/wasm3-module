/*
 * main.c - Test out kernel space WASM.
 */

#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>

#include "m3_env.h"
#include "wasm3.h"

#include "wasm/prog.wasm.c"
/**
 * DEFINES
 */

#define WASM_STACK_SIZE 64 * 1024 // 64 KB stack
#define PROC_NAME "net_trace_stats"
#define DEV_WASM_PROG_LOAD "wasm_prog_load"
#define IOCTL_SEND_BYTES_WITH_SIZE _IOW('a', 2, struct wasm_data)

/**
 * Gloabl decls and defs
 */

static char *kernel_buffer = NULL;


static atomic_t packet_count = ATOMIC_INIT(0);
static struct proc_dir_entry *proc_file;
IM3Runtime runtime;
IM3Environment env;


struct wasm_data {
  char *data;
  size_t size;
  char *hook_cmd; // currently redundant
};

// Temporary fix to process sequentially
DEFINE_MUTEX(lock);

/**
 * Load and prepare the WASM program.
 */

static long load_prog_into_runtime(size_t wasm_size_r) {

  // Parse the new module
  IM3Module module;
  M3Result result = m3_ParseModule(env, &module, kernel_buffer, wasm_size_r); // is kernel_buffer the right format?
  if (result) {
    pr_err("Error parsing module: %s\n", result);
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    return (-1);
  }

  pr_info("Parsed new module\n");

  // Load it into the runtime so it becomes available for the hook function to use.
  result = m3_LoadModule(runtime, module);
  if (result) {
    pr_err("Error loading module: %s\n", result);
    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    return (-1);
  }

  pr_info("Loaded new module into wasm runtime\n");

  return 0;
}

/**
 * Filter Function
 * 
 * The filter function will look for the function nf_filter in the userspace wasm code.
 * If this function is found, it will call it (without args) and return the result.
 * The result is what should be returned from the kernel nf_filter function
 * because this decides what happens with the packet.
 * 
 * The current userspace nf_filter implementation simply drops all the packets.
 * 
 * @todo: Since we want fine tuned parsing of the packet, the user should create (or be provided with)
 * some structures which can be used to extract headers. This will allow for more complex filtering.
 * 
 * @todo: Pre-define new runtimes for each physical core.
 */

static unsigned int nf_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    // Find the nf_filter() function in the WASM module.
    IM3Function nf_filter_func;
    uint32_t nf_ret_val = 1;
    mutex_lock(&lock);
    int find_result = m3_FindFunction(&nf_filter_func, runtime, "nf_filter");
    if (find_result) {
      pr_err("Error finding function: %s\n", find_result);
      return NF_ACCEPT;
    }

    // Call the nf_filter() function.
    M3Result result = m3_CallV(nf_filter_func);
    if (result) {
      pr_err("Error calling function: %s\n", result);
      return NF_ACCEPT;
    }

    // Get results of the call which can be one of NF_ACCEPT, NF_DROP, etc.
    result = m3_GetResultsV(nf_filter_func, &nf_ret_val);
    if (result) {
      pr_err("Error getting results: %s\n", result);
      return (-1);
    }
    mutex_unlock(&lock);
    // The return value decides the behaviour of the filter
    return nf_ret_val;
}

static struct nf_hook_ops nfho = {
    .hook = nf_filter,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
};


/**
 * Register the wrapper filter function which calls the actual
 * function defined in prog.wasm and which is loaded into the runtime.
 */
static long register_nf_filter(void) {
  
  int ret = nf_register_net_hook(&init_net, &nfho);
  if (ret < 0) {
    pr_err("Failed to register netfilter hook\n");
    remove_proc_entry(PROC_NAME, NULL);
    return ret;
  }

  pr_info("Registered netfilter hook\n");
  return 0;
}

static long wasm_prog_load(struct file *f, unsigned int cmd,
                           unsigned long arg) {
  struct wasm_data wdata;

  switch (cmd) {
  case IOCTL_SEND_BYTES_WITH_SIZE:
    if (copy_from_user(&wdata, (struct wasm_data *)arg,
                       sizeof(struct wasm_data))) {
      pr_err("Failed to copy wasm_data structure from userspace\n");
      return -EFAULT;
    }

    pr_info("Received %zu bytes from userspace\n", wdata.size);

    if (kernel_buffer == NULL) {
      kernel_buffer = kmalloc(wdata.size, GFP_KERNEL);
      if (!kernel_buffer) {
        pr_err("Failed to allocate kernel buffer\n");
        return -ENOMEM;
      }
    }

    if (copy_from_user(kernel_buffer, wdata.data, wdata.size)) {
      pr_err("Failed to copy data from userspace\n");
      return -EFAULT;
    }

    pr_info("Copied %zu bytes from userspace\n", wdata.size);

    // Load the WASM program into the runtime
    int load_ret = load_prog_into_runtime(wdata.size);
    if (load_ret < 0) {
      pr_err("Failed to load WASM program\n");
      return load_ret;
    }

    // Finally, register the hook
    int reg_ret = register_nf_filter();
    if (reg_ret < 0) {
      pr_err("Failed to register netfilter hook\n");
      return reg_ret;
    }

    break;

  default:
    pr_err("Invalid command\n");
    return -EINVAL;
  }
  return 0;
}




/**
 * Proc functions
 */
static int proc_show(struct seq_file *m, void *v) {
  seq_printf(m, "Packet count: %d\n", atomic_read(&packet_count));
  return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
  return single_open(file, proc_show, NULL);
}


/**
 * Proc and NF Hook structs
 */
static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static struct file_operations fops = {
    .unlocked_ioctl = wasm_prog_load,
};


/*
 * Called when the kernel module is loaded.
 */
int init_module(void) {
  // Initialize the device file for comms between us and ks
  int reg_ret = register_chrdev(371, DEV_WASM_PROG_LOAD, &fops);
  if (reg_ret < 0) {
    pr_err("Failed to register device\n");
    return reg_ret;
  }

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

  // Create the proc file.
  proc_file = proc_create(PROC_NAME, 0444, NULL, &proc_fops);
  if (!proc_file) {
    pr_err("Failed to create proc entry\n");
    return -ENOMEM;
  }

  return (0);
}

/*
 * Called when the kernel module is unloaded.
 */
void cleanup_module(void) {
  // Just print a goodbye message for now.
  remove_proc_entry(PROC_NAME, NULL);
  nf_unregister_net_hook(&init_net, &nfho);

  m3_FreeRuntime(runtime);
  m3_FreeEnvironment(env);

  unregister_chrdev(371, DEV_WASM_PROG_LOAD);

  if (kernel_buffer) {
    kfree(kernel_buffer);
  }

  pr_info("Network trace module unloaded\n");
  pr_info("Goodbye!\n");
}

MODULE_LICENSE("Dual BSD/GPL");