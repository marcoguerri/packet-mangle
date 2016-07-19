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
#include "libcrc/crc.h"

static struct nf_hook_ops hook_options;

unsigned int 
mangling_hook(void *priv,
              struct sk_buff *skb,
              const struct nf_hook_state *state)
{

    struct iphdr *iph;
    struct tcphdr *tcph;

    u8* tcp_pl;
    u8 signature[2] = {0x0A, 0x0A};
    u64 np_data_tcp_pl = 0;
    
    crc_t crc;
    crc_params_t crc_params;
   
    /* Get IP header and check the transport protocol. Proceed only if it's TCP */
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    /* Check if the skb is linear. If not, do not consider it. Linear means
     * skb->data_len is == 0 */
    if(skb_is_nonlinear(skb)) 
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    tcp_pl = (u8*)((u8*)tcph + (tcph->doff * 4));
    np_data_tcp_pl = (u64)(skb_tail_pointer(skb) - tcp_pl);

    if(np_data_tcp_pl >= 2 && memcmp(&signature, tcp_pl, 2) == 0)
    {
        // Some debug info  
        //printk(KERN_INFO "Linear data: %u\n", skb_headlen(skb));
        //printk(KERN_INFO "Linear data TCP payload: %lu\n", np_data_tcp_pl);

        crc_params.type = CRC32;
        crc_params.poly.poly_crc32 = 0x04C11DB7;
        crc_params.crc_init.crc32 = 0xFFFFFFFF;
        crc_params.flags = CRC_INPUT_REVERSAL | 
                           CRC_OUTPUT_REVERSAL | 
                           CRC_OUTPUT_INVERSION;

        crc = crc_fast(&crc_params,(uint8_t*)skb->data, skb_headlen(skb));

        printk(KERN_INFO "CRC before corruption: %x\n", crc.crc32);
        *(tcp_pl) = 0x00;
        *(tcp_pl+1) = 0x00;

        crc = crc_fast(&crc_params,(uint8_t*)skb->data, skb_headlen(skb));
        printk(KERN_INFO "CRC after corruption: %x\n", crc.crc32);

        /* Leave checksum as it is */
        skb->ip_summed = CHECKSUM_NONE;

    }

    return NF_ACCEPT;
}

/**
 * Registers the hook
 */
static int 
register_hook(void)
{
    hook_options.hook = (unsigned int (*)(void *,
                                         struct sk_buff*, 
                                         const struct nf_hook_state*))mangling_hook;

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
