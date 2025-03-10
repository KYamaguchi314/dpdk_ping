#include <inttypes.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define PACKET_MARK_ICMP_REQUEST 1
#define PACKET_MARK_ICMP_REPLY 2

uint32_t my_ipaddr = RTE_IPV4(10, 255, 0, 1);
uint32_t target_ipaddr = RTE_IPV4(10, 255, 0, 2);

struct rte_ether_addr my_macaddr;
struct rte_ether_addr target_macaddr = {0};
struct rte_ether_addr empty_macaddr = {0, 0, 0, 0, 0, 0};
struct rte_ether_addr broadcast_macaddr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct rte_ring *tx_ring;
struct rte_ring *rx_ring;

struct packet {
    struct rte_mbuf *m;

    uint8_t is_tx;
    uint64_t tsc;
    uint64_t tsc_hz;
    uint64_t mark;
};

static struct {
    uint16_t ident;
    uint16_t seq;
    uint64_t last_sent_tsc;
} ping_info;

static unsigned short checksum(unsigned short *ptr, int len) {
    unsigned long sum = 0;
    while (len > 0) {
        sum += *ptr++;
        len -= sizeof(unsigned short);
    }
    if (len) {
        sum += *(char *)ptr;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

struct arp_request_packet {
    struct rte_ether_hdr eth;
    struct rte_arp_hdr arph;
};

static void enqueue_arp_request_packet(struct rte_mempool *mbuf_pool) {
    struct rte_mbuf *m;

    if ((m = rte_pktmbuf_alloc(mbuf_pool)) == NULL) {
        printf("failed to alloc mbuf\n");
        return;
    }
    if (rte_pktmbuf_append(m, sizeof(struct arp_request_packet)) == NULL) {
        printf("failed to append\n");
        return;
    }

    /* ether */
    struct arp_request_packet *msg =
        rte_pktmbuf_mtod(m, struct arp_request_packet *);

    rte_ether_addr_copy(&my_macaddr, &msg->eth.src_addr);
    rte_ether_addr_copy(&broadcast_macaddr, &msg->eth.dst_addr);
    msg->eth.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    /* arp */
    msg->arph.arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    msg->arph.arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    msg->arph.arp_hlen = RTE_ETHER_ADDR_LEN;
    msg->arph.arp_plen = 4;
    msg->arph.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
    rte_ether_addr_copy(&my_macaddr, &msg->arph.arp_data.arp_sha);
    rte_ether_addr_copy(&empty_macaddr, &msg->arph.arp_data.arp_sha);
    msg->arph.arp_data.arp_sip = rte_cpu_to_be_32(my_ipaddr);
    msg->arph.arp_data.arp_tip = rte_cpu_to_be_32(target_ipaddr);

    /* enqueue arp request */
    struct packet *pkt = rte_malloc(NULL, sizeof(struct packet), 0);
    if (pkt == NULL) {
        printf("failed to malloc\n");
        return;
    }
    pkt->m = m;
    rte_ring_enqueue(tx_ring, pkt);
}

struct icmp_request_packet {
    struct rte_ether_hdr eth;
    struct rte_ipv4_hdr iph;
    struct rte_icmp_hdr icmph;
    char payload[20];
};

static void enqueue_icmp_echo_packet(struct rte_mempool *mbuf_pool) {
    struct rte_mbuf *m;

    if ((m = rte_pktmbuf_alloc(mbuf_pool)) == NULL) {
        printf("failed to alloc mbuf\n");
        return;
    }
    if (rte_pktmbuf_append(m, sizeof(struct icmp_request_packet)) == NULL) {
        printf("failed to append\n");
        return;
    }

    struct icmp_request_packet *msg =
        rte_pktmbuf_mtod(m, struct icmp_request_packet *);

#ifndef DPDK_BOUNCE
    if (rte_is_same_ether_addr(&target_macaddr, &empty_macaddr)) {
        /* enqueue arp request */
        printf("macaddr is not resolved yet\n");
        enqueue_arp_request_packet(mbuf_pool);
        return;
    }
#endif

    /* ether */
    rte_ether_addr_copy(&my_macaddr, &msg->eth.src_addr);
    rte_ether_addr_copy(&target_macaddr, &msg->eth.dst_addr);
    msg->eth.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* ipv4 */
    msg->iph.version = 4;
    msg->iph.ihl = sizeof(struct rte_ipv4_hdr) / 4;
    msg->iph.src_addr = rte_cpu_to_be_32(my_ipaddr);
    msg->iph.dst_addr = rte_cpu_to_be_32(target_ipaddr);
    msg->iph.total_length =
        rte_cpu_to_be_16(sizeof(struct icmp_request_packet) -
                         offsetof(struct icmp_request_packet, iph));
    msg->iph.time_to_live = 64;
    msg->iph.next_proto_id = 1;
    msg->iph.hdr_checksum = 0;
    msg->iph.hdr_checksum = rte_ipv4_cksum(&msg->iph);

    /* icmp */
    msg->icmph.icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
    msg->icmph.icmp_code = 0;
    msg->icmph.icmp_ident = rte_cpu_to_be_16(ping_info.ident);
    msg->icmph.icmp_seq_nb = rte_cpu_to_be_16(ping_info.seq);
    msg->icmph.icmp_cksum = 0;
    char payload[] = "hello, world!";
    memcpy(&msg->payload, payload, sizeof(payload));

    msg->icmph.icmp_cksum =
        checksum((unsigned short *)&msg->icmph,
                 sizeof(struct icmp_request_packet) -
                     offsetof(struct icmp_request_packet, icmph));

    /* enqueue icmp request */
    struct packet *pkt = rte_malloc(NULL, sizeof(struct packet), 0);
    if (pkt == NULL) {
        printf("failed to malloc\n");
        return;
    }
    pkt->m = m;
    pkt->mark = PACKET_MARK_ICMP_REQUEST;
    rte_ring_enqueue(tx_ring, pkt);
}

static int receive(struct packet *pkt) {
    struct rte_ether_hdr *eth_hdr =
        rte_pktmbuf_mtod(pkt->m, struct rte_ether_hdr *);

#ifdef DPDK_BOUNCE
    if (rte_is_same_ether_addr(&eth_hdr->src_addr, &my_macaddr)) {
        /* 受信したパケットのsrc macaddrが自分だったら、打ち返したパケット */
        pkt->mark = PACKET_MARK_ICMP_REPLY;
        return true;
    }
#endif

    if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        /* arp */
        struct rte_arp_hdr *arp_hdr =
            (struct rte_arp_hdr *)(char *)(eth_hdr + 1);
        // printf("arp target ip: %d.%d.%d.%d\n",
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_tip) >> 24) & 0xff,
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_tip) >> 16) & 0xff,
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_tip) >> 8) & 0xff,
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_tip) >> 0) & 0xff);
        // printf("arp source ip: %d.%d.%d.%d\n",
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip) >> 24) & 0xff,
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip) >> 16) & 0xff,
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip) >> 8) & 0xff,
        //        (rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip) >> 0) & 0xff);
        if (arp_hdr->arp_data.arp_tip != rte_cpu_to_be_32(my_ipaddr)) {
            printf("arp\n");
            return 0;
        }

        if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
            printf("arp request\n");
            /* eth */
            rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
            rte_ether_addr_copy(&my_macaddr, &eth_hdr->src_addr);
            /* arp */
            arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
            rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha,
                                &arp_hdr->arp_data.arp_tha);
            rte_ether_addr_copy(&my_macaddr, &arp_hdr->arp_data.arp_sha);
            arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
            arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(my_ipaddr);

            /* enqueue icmp request */
            struct packet *pkt_reply =
                rte_malloc(NULL, sizeof(struct packet), 0);
            if (pkt_reply == NULL) {
                printf("failed to malloc\n");
                return false;
            }
            pkt_reply->m = pkt->m;
            pkt->m = NULL;
            rte_ring_enqueue(tx_ring, pkt_reply);
        } else if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
            printf("arp reply\n");
            rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &target_macaddr);
        }

    } else if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        /* ipv4 */
        struct rte_ipv4_hdr *ip_hdr =
            (struct rte_ipv4_hdr *)(char *)(eth_hdr + 1);

        if (ip_hdr->dst_addr != rte_cpu_to_be_32(my_ipaddr)) {
            printf("ipv4\n");
            return 0;
        }

        const size_t ip_data_len =
            rte_be_to_cpu_16(ip_hdr->total_length) - ip_hdr->ihl * 4;

        if (ip_hdr->next_proto_id == 1) {
            /* icmp */
            struct rte_icmp_hdr *icmp_hdr =
                (struct rte_icmp_hdr *)(char *)(ip_hdr + 1);

            if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REPLY) {
                printf("icmp echo reply from %d.%d.%d.%d\n",
                       (rte_be_to_cpu_32(ip_hdr->src_addr) >> 24) & 0xff,
                       (rte_be_to_cpu_32(ip_hdr->src_addr) >> 16) & 0xff,
                       (rte_be_to_cpu_32(ip_hdr->src_addr) >> 8) & 0xff,
                       (rte_be_to_cpu_32(ip_hdr->src_addr) >> 0) & 0xff);
                pkt->mark = PACKET_MARK_ICMP_REPLY;
            } else if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
                /* eth */
                rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                rte_ether_addr_copy(&my_macaddr, &eth_hdr->src_addr);
                /* ip */
                ip_hdr->dst_addr = ip_hdr->src_addr;
                ip_hdr->src_addr = rte_be_to_cpu_32(my_ipaddr);
                ip_hdr->hdr_checksum = 0;
                ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
                /* icmp */
                icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
                icmp_hdr->icmp_cksum = 0;
                icmp_hdr->icmp_cksum =
                    checksum((unsigned short *)&icmp_hdr, ip_data_len);

                /* enqueue icmp request */
                struct packet *pkt_reply =
                    rte_malloc(NULL, sizeof(struct packet), 0);
                if (pkt_reply == NULL) {
                    printf("failed to malloc\n");
                    return false;
                }
                pkt_reply->m = pkt->m;
                pkt->m = NULL;
                rte_ring_enqueue(tx_ring, pkt_reply);
            } else {
                printf("unsupported icmp type: %d\n", icmp_hdr->icmp_type);
            }
        } else {
            printf("unsupported ipv4 proto: %d\n", ip_hdr->next_proto_id);
        }
    } else {
        printf("unsupported ether type 0x%04x\n",
               rte_be_to_cpu_16(eth_hdr->ether_type));
    }

    return true;
}
