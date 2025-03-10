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

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                            struct rte_ether_addr *addr_out) {
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    retval = rte_eth_macaddr_get(port, addr_out);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", port,
           RTE_ETHER_ADDR_BYTES(addr_out));

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

/**
 * すべてのportがlink upするまで待機
 */
static void wait_linkup(uint32_t port_mask) {
    const int CHECK_INTERVAL_MS = 100;
    const int MAX_CHECK_COUNT = 1000;

    int ret;
    uint16_t portid;
    uint8_t all_ports_up;
    struct rte_eth_link link;
    char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

    for (int c = 0; c <= MAX_CHECK_COUNT; c++) {
        all_ports_up = true;
        RTE_ETH_FOREACH_DEV(portid) {
            if ((port_mask & (1 << portid)) == 0)
                continue;

            memset(&link, 0, sizeof(link));
            ret = rte_eth_link_get_nowait(portid, &link);
            if (ret < 0) {
                all_ports_up = false;
                printf("Port %u link get failed: %s\n", portid,
                       rte_strerror(-ret));
                continue;
            }

            if (link.link_status == RTE_ETH_LINK_DOWN) {
                all_ports_up = false;
                break;
            }

            printf("\n");
            rte_eth_link_to_str(link_status_text, sizeof(link_status_text),
                                &link);
            printf("Port %d %s\n", portid, link_status_text);
        }

        if (all_ports_up) {
            break;
        } else {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL_MS);
        }
    }
}
