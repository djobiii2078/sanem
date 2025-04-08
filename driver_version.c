// File: sanem_module.c

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/netdevice.h>
#include <linux/sched.h>

#define PROCFS_NAME "sanem_stats"
#define TIMER_INTERVAL (10 * HZ)  // 10 seconds

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Djob");
MODULE_DESCRIPTION("SANEM: Security-aware Network & ICC Monitor");
MODULE_VERSION("0.1");

static struct timer_list sanem_timer;
static struct proc_dir_entry *sanem_proc_file;

static unsigned long total_rx_packets = 0;
static unsigned long total_tx_packets = 0;

#define MAX_RESTRICTED_APPS 10

// Simulated restricted UID list
static const uid_t restricted_uids[MAX_RESTRICTED_APPS] = {
    10086, 10123 // Example UIDs for restricted apps
};

static bool is_uid_restricted(uid_t target_uid) {
    int i;
    for (i = 0; i < MAX_RESTRICTED_APPS; ++i) {
        if (restricted_uids[i] == target_uid) {
            return true;
        }
    }
    return false;
}

// Collect basic network stats from all net devices
static void collect_network_stats(void) {
    struct net_device *dev;

    total_rx_packets = 0;
    total_tx_packets = 0;

    read_lock(&dev_base_lock);
    for_each_netdev(&init_net, dev) {
        total_rx_packets += dev->stats.rx_packets;
        total_tx_packets += dev->stats.tx_packets;
    }
    read_unlock(&dev_base_lock);
}

// Timer callback for periodic monitoring
static void sanem_timer_callback(struct timer_list *t) {
    collect_network_stats();
    mod_timer(&sanem_timer, jiffies + TIMER_INTERVAL);
}

// /proc file read handler
static ssize_t sanem_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    char buffer[256];
    int len;

    len = snprintf(buffer, sizeof(buffer),
                   "SANEM Network Stats:\nRX: %lu packets\nTX: %lu packets\n",
                   total_rx_packets, total_tx_packets);

    return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static const struct proc_ops proc_file_ops = {
    .proc_read = sanem_read,
};

// Stub for ICC restriction hook (To Be Expanded)
static void enforce_icc_restrictions(uid_t target_uid) {
    if (is_uid_restricted(target_uid)) {
        pr_warn("SANEM: ICC to UID %d is restricted! Action blocked/logged.\n", target_uid);
        // Optional: block the transaction if this were a real hook
    } else {
        pr_info("SANEM: ICC to UID %d allowed.\n", target_uid);
    }
}

static int __init sanem_init(void) {
    pr_info("SANEM module loaded\n");

    // Create proc entry
    sanem_proc_file = proc_create(PROCFS_NAME, 0444, NULL, &proc_file_ops);
    if (!sanem_proc_file) {
        pr_err("SANEM: Failed to create /proc entry\n");
        return -ENOMEM;
    }

    // Setup timer
    timer_setup(&sanem_timer, sanem_timer_callback, 0);
    mod_timer(&sanem_timer, jiffies + TIMER_INTERVAL);

    return 0;
}

static void __exit sanem_exit(void) {
    del_timer_sync(&sanem_timer);
    proc_remove(sanem_proc_file);
    pr_info("SANEM module unloaded\n");
}

module_init(sanem_init);
module_exit(sanem_exit);
