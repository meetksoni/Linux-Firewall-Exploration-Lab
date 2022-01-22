# Linux-Firewall-Exploration-Lab
# Check the IP addresses of all Machines
# Using Firewall - Prevent Machine 1 from doing telnet to Machine B
- Command:  sudo iptables –A OUTPUT –p tcp –s 10.0.2.5  --dport 23 –j DROP

# Using Firewall - Prevent Machine B from doing telnet to Machine A.
- Command: sudo iptables –A INPUT –p tcp –s 10.0.2.6  --dport 23 –j DROP

# Using Firewall - Prevent A from visiting an external web site. 
- Finding the IP address oof the external website ‘www.bhavans.ac.in”. Secondly, blocking the Machine 1 access to the external website www.bhavans.ac.in using the iptables. 

# Implementing a Simple Firewall
- Create a folder named “task2” in Documents folder.
- Create a “fwcode.c” file for our netfilter firewall rules.
- This is the code for our file “fwcode.c”.
- Create a “Makefile”.
- Using “make” command.
- Using “sudo insmod fwcode.ko” to insert the module “fwcode.ko” into the kernel space.
- Check in the syslog that the filter is registered. 

#  Evading Egress Filtering

# Evading Ingress Filtering

# Appendix 

Codes Used in the Lab 1.
# ---------Zcode.c Code----------
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>

static struct nf_hook_ops Filter_Hook;
static struct nf_hook_ops Out_Filter_Hook;

unsigned int filter_code(void *priv, struct sk_buff *skb,
const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);
	tcph = (void*)iph + iph -> ihl*4;
	if(iph -> protocol == IPPROTO_TCP && tcph -> dest == htons(23) && iph -> saddr == in_aton("10.0.2.8"))
	{
		printk("Prevent Machine 2 from doing telnet to Machine 1.\n");
		return NF_DROP;
	}
	else if(iph -> protocol == IPPROTO_ICMP  && iph -> saddr == in_aton("10.0.2.8"))
	{
		printk("Prevent ping from Machine 2.\n");
		return NF_DROP;
	}
	else if(iph -> protocol == IPPROTO_TCP && tcph -> dest == htons(23) && iph -> saddr == in_aton("10.0.2.9"))
	{
		printk("Prevent Machine 3 from doing telnet to Machine 1\n");
		return NF_DROP;
	}
	else
	{
		return NF_ACCEPT;
	}
}

unsigned int Outfilter_code(void *priv, struct sk_buff *skb,
const struct nf_hook_state *state)
{
        struct iphdr *iph;
        struct tcphdr *tcph;
        iph = ip_hdr(skb);
        tcph = (void*)iph + iph -> ihl*4;
	if(iph -> protocol == IPPROTO_TCP && tcph -> dest == htons(23) && iph -> saddr == in_aton("10.0.2.7"))
        {
                printk("Prevent Machine 1 from doing telnet to Machine 2.\n");
                return NF_DROP;
        }
        else if(iph -> protocol == IPPROTO_ICMP && iph -> daddr == in_aton("160.153.138.53"))
        {
                printk("Prevent Machine 1 from reaching the external website www.bhavans.ac.in \n");
                return NF_DROP;
        }
	else 
	{
		return NF_ACCEPT;
	}
}

int SetUpFilter(void)
{
	printk(KERN_INFO "Register Filter\n");
	Filter_Hook.hook = filter_code;
	Filter_Hook.hooknum = NF_INET_PRE_ROUTING;
	Filter_Hook.pf = PF_INET;
	Filter_Hook.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net,&Filter_Hook);
	Out_Filter_Hook.hook = Outfilter_code;
        Out_Filter_Hook.hooknum = NF_INET_POST_ROUTING;
        Out_Filter_Hook.pf = PF_INET;
        Out_Filter_Hook.priority = NF_IP_PRI_FIRST;	
	nf_register_net_hook(&init_net,&Out_Filter_Hook);
	return 0;
}

void RemoveFilter(void)
{
	printk(KERN_INFO "Filter is removed.\n");
	nf_unregister_net_hook(&init_net,&Filter_Hook);
	nf_unregister_net_hook(&init_net,&Out_Filter_Hook);
}
module_init(SetUpFilter);
module_exit(RemoveFilter);

# ---------Makefile Code---------
obj-m += zcode.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

