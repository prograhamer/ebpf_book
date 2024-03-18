#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

static __always_inline struct icmphdr *icmp_thingy(void *data,
                                                   void *data_end)
{
  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end)
    return NULL;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return NULL;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return NULL;

  if (iph->protocol != 0x01)
    // We're only interested in ICMP packets
    return NULL;

  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct icmphdr) >
      data_end)
    return NULL;

  return icmp;
}

int xdp(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct icmphdr *icmp = icmp_thingy(data, data_end);
  if (icmp == NULL)
  {
    return XDP_PASS;
  }
  if (icmp->type == ICMP_ECHO)
  {

    bpf_trace_printk("Got an echo request with ID %u sequence number %u", bpf_ntohs(icmp->un.echo.id), bpf_ntohs(icmp->un.echo.sequence));
  }

  if (icmp->type == ICMP_ECHOREPLY)
  {
    bpf_trace_printk("Got an echo response with ID %u sequence number %u", bpf_ntohs(icmp->un.echo.id), bpf_ntohs(icmp->un.echo.sequence));
  }
  return XDP_PASS;
}
