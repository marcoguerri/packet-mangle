/* 
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 *   Author: Marco Guerri <gmarco.dev@gmail.com>
 *
 */
#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops hook_options;

unsigned int 
mangling_hook(unsigned int hook_num,
              struct sk_buff *skb,
              const struct net_device *in,
              const struct net_device *out,
              int (*okfn)(struct sk_buff *))  
{

    struct iphdr *iph;
    struct tcphdr *tcph;
    /*
     * Get IP header and check the transport protocol. Proceed only if it's
     * TCP
     */
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);

    /* Get a pointer to the TCP payload */
    u8* tcp_pl;
    u8 signature[2] = {0x0A, 0x0B};
    u64 np_data_tcp_pl = 0;
    
    tcp_pl = (u8*)((u8*)tcph + (tcph->doff * 4));
    if(memcmp(&signature, tcp_pl, 2) == 0)
    {
        printk(KERN_INFO "Signature detected\n");

        if(skb->data_len != 0) 
            printk(KERN_INFO "Non linear data present\n");
        
        printk(KERN_INFO "Linear data: %u\n", skb_headlen(skb));
        np_data_tcp_pl = (u64)(skb_tail_pointer(skb) - tcp_pl);
        printk(KERN_INFO "Linear data TCP payload: %lu\n", np_data_tcp_pl);

        if(np_data_tcp_pl >= 3)
            printk(KERN_INFO "Can do some mangling here! 0x%x\n", tcp_pl[2]);
    }

    return NF_ACCEPT;
}

/**
 * Registers the hook
 */
static int 
register_hook(void)
{
    hook_options.hook = (unsigned int(*)(unsigned int, 
                                         struct sk_buff*, 
                                         const struct net_device*, 
                                         const struct net_device*, 
                                         int (*)(struct sk_buff*)))mangling_hook;

    hook_options.hooknum = NF_INET_POST_ROUTING;
    hook_options.pf = PF_INET;
    hook_options.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&hook_options);
    return 0;
}

/**
 * Unregisters the hook
 */
static int
unregister_hook(void)
{
    nf_unregister_hook(&hook_options);
    return 0;
}

static int 
__init mangle_init(void)
{
    printk(KERN_INFO "Registering hook\n");
    register_hook();
    return 0; 
}

static void 
__exit mangle_exit(void)
{
    printk(KERN_INFO "Unregistering hook\n");
    unregister_hook();
}

module_init(mangle_init);
module_exit(mangle_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Guerri");
MODULE_DESCRIPTION("Module which allows to mangle outgoing packets");
