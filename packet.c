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
#include <net/tcp.h>
#include <linux/netfilter_ipv4.h>

#include "checksum.h"

#define TCP_PSEUDOHEADER_LEN 12

static struct nf_hook_ops hook_options;

unsigned int 
mangling_hook(void *priv,
              struct sk_buff *skb,
              const struct nf_hook_state *state)
{

    struct iphdr *iph;
    struct tcphdr *tcph;

    u8 *tcp_payload, *buffer;
    struct tcp_pseudohdr_t *pseudo_header; 
    u8 signature[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    u32 tcp_payload_len = 0, tcp_header_len = 0;
    uint16_t checksum;

    // TODO: Check we are working with IPv4
    
    /* Get IP header and check the transport protocol. Proceed only if it's TCP */
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    /* Check if the skb is linear. If not, do not consider it. Linear means
     * skb->data_len is == 0 */
    if(skb_is_nonlinear(skb)) 
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);

    tcp_payload = (u8*)((u8*)tcph + (tcph->doff * 4));
    tcp_payload_len = (u64)(skb_tail_pointer(skb) - tcp_payload);
    tcp_header_len = tcph->doff * 4;

	
    printk(KERN_INFO "%lu\n", sizeof(struct tcp_pseudohdr_t));
    if(tcp_payload_len >= 4 && memcmp(&signature, tcp_payload, 4) == 0)
    {
        /* Some debug info */
        printk(KERN_INFO "Linear data: %u\n", skb_headlen(skb));
        printk(KERN_INFO "TCP payload len is %u\n", tcp_payload_len);
        printk(KERN_INFO "TCP header len is %x\n", tcp_header_len);
        /* 
         * Calculating the TCP checksum: bulding pseudoheader and constructing the
         * buffer to be passed to tcp_checksum function.
         */
        pseudo_header = (struct tcp_pseudohdr_t*)kmalloc(TCP_PSEUDOHEADER_LEN, GFP_KERNEL);
        if(!pseudo_header)
        {
            printk(KERN_DEBUG "Error while allocating memory for pseudo header\n");
            return NF_ACCEPT;
        }
        tcp_build_pseudoheader(iph, tcp_header_len + tcp_payload_len, pseudo_header);
    
        buffer = (uint8_t*)kmalloc(TCP_PSEUDOHEADER_LEN + tcp_header_len + tcp_payload_len, GFP_KERNEL);
         if(!buffer)
        {
            printk(KERN_DEBUG "Error while allocating memory for buffer\n");
            return NF_ACCEPT;
        }    
        
        memcpy(buffer, pseudo_header, sizeof(struct tcp_pseudohdr_t));
        
        /* Zeroing out checksum in TCP header before calculating checksum */
        tcph->check = 0x0000;
        memcpy(buffer + sizeof(struct tcp_pseudohdr_t), tcph, tcp_header_len + tcp_payload_len);
        checksum = tcp_checksum(buffer, sizeof(struct tcp_pseudohdr_t) + tcp_header_len + tcp_payload_len);

        printk(KERN_INFO "TCP checksum should be 0x%04x\n", htons(checksum));

        /* Can double check by using tcp_v4_check */
        uint16_t checksum_kernel = tcp_v4_check( 
                         tcp_header_len + tcp_payload_len, 
	 	         iph->saddr, 
                         iph->daddr, 
		         csum_partial((char *)tcph, tcp_header_len + tcp_payload_len, 0)); 
        printk(KERN_INFO "Checksum from kernel 0x%04x\n", checksum_kernel);
        //tcph->check = htons(checksum);
    
        /* Corrupting checksum */
        checksum = 0xBEEF;
        tcph->check = htons(checksum);
        printk(KERN_INFO "Corrupting checksum to 0xBEEF\n");
        
        kfree(buffer);
        kfree(pseudo_header);

        /* Write TCP checksum and tell Kernel/Driver/Hardware not to re-calculate it */
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
