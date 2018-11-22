#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>

//struct holding set of hook funtion options
static struct nf_hook_ops nfho;
//initialize window size
static unsigned int size = 0;

//function to be called by hook
unsigned int hook_func_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
    struct iphdr *ip = ip_hdr(skb);
    struct tcphdr *tcp = tcp_hdr(skb);
    
    //get the TCP window size
    unsigned char *wins =(unsigned char *)&(tcp->window);
    unsigned int cursize = tcp->window;
    if(cursize != size){
        //output the window size if changed. Reverse the order in struct and change it to dec.
        printk("window size change to: %d%d%d%d\n",wins[3]&0xff, wins[2]&0xff, wins[1]&0xff, wins[0]&0xff);
        size = cursize;
    }
    
    return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module(){
    //function to call when conditions below met
    nfho.hook = hook_func_incoming;

    //called right after packet received, firest hook in Netfilter
    nfho.hooknum = NF_INET_PRE_ROUTING;

    //IPV4 packets
    nfho.pf = PF_INET;

    //set to highest priority over all other hook functions
    nfho.priority = NF_IP_PRI_FIRST;

    //register hook
    nf_register_hook(&nfho);

    printk(KERN_INFO "simple firewall loaded\n");
    return 0;
}
void cleanup_module()
{ 
  printk("simple firewall unloaded\n");
  nf_unregister_hook(&nfho);                //cleanup and unregister hook
}
