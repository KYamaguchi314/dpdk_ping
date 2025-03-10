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

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

struct rte_mempool *mbuf_pool;
static int force_quit = false;

/**
 * 何回pingしたら終了するか
 */
static int quit_count_max = 1000;
static int quit_count = 0;

#define PACKET_MARK_ICMP_REQUEST 1
#define PACKET_MARK_ICMP_REPLY 2

#include "link.h"
#include "protocol.h"

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        printf("\n\nSignal %s received, preparing to exit...\n",
               strsignal(signum));
        force_quit = true;
    }
}

/**
 * 送受信処理、タイムスタンプ押下
 */
static void lcore_main(void *)
{
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    unsigned lcore_id;
    uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
    unsigned i, j, portid, nb_rx, nb_tx;
    const uint64_t drain_tsc = rte_get_tsc_hz() * 0.000100;

    while (!force_quit)
    {
        cur_tsc = rte_rdtsc();
        uint64_t tsc_hz = rte_get_tsc_hz();

        /* 送信 */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc))
        {
            struct packet *pkt;
            if (rte_ring_dequeue(tx_ring, (void **)&pkt) == 0)
            {
                uint8_t sent = rte_eth_tx_burst(portid, 0, &pkt->m, 1);
                if (sent > 0)
                {
                    pkt->m = NULL;
                    pkt->is_tx = true;
                    pkt->tsc = cur_tsc;
                    pkt->tsc_hz = tsc_hz;
                    rte_ring_enqueue(rx_ring, pkt);
                }
            }
            prev_tsc = cur_tsc;
        }

        /* 受信 */
        nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, BURST_SIZE);

        for (j = 0; j < nb_rx; j++)
        {
            struct rte_mbuf *m = pkts_burst[j];
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));

            struct packet *pkt = rte_malloc(NULL, sizeof(struct packet), 0);
            if (pkt == NULL)
            {
                printf("failed to malloc\n");
                break;
            }
            pkt->m = m;
            pkt->is_tx = false;
            pkt->tsc = cur_tsc;
            pkt->tsc_hz = tsc_hz;
            rte_ring_enqueue(rx_ring, pkt);
        }
    }
}

/**
 * 定期的に icmp echo パケットをenqueueする
 */
static int lcore_generate_packet(void *)
{
    while (!force_quit)
    {
        enqueue_icmp_echo_packet(mbuf_pool);
        rte_delay_us_sleep(100000);
    }
}

/**
 * プロトコルスタック
 */
static int lcore_protocol_stack(void *)
{
    struct packet *pkt;
    unsigned nb_rx;
    FILE *fp = fopen("log.jsonl", "wt");

    while (!force_quit)
    {
        if (rte_ring_dequeue(rx_ring, (void **)&pkt) == 0)
        {
            /* 受信時はプロトコルスタックに渡す */
            if (!pkt->is_tx)
                receive(pkt);

            /* ログに出力 */
            if (pkt->mark > 0)
            {
                fprintf(fp, "{\"tsc\":%ld,\"tsc_hz\":%ld,\"mark\":%ld}\n",
                        pkt->tsc, pkt->tsc_hz, pkt->mark);
                fflush(fp);
                if (pkt->mark == PACKET_MARK_ICMP_REPLY)
                {
                    printf("%d/%d\n", quit_count + 1, quit_count_max);
                    if (quit_count >= quit_count_max - 1)
                        force_quit = true;
                    quit_count++;
                }
            }

            /* 片付け */
            if (pkt->m)
                rte_pktmbuf_free(pkt->m);
            rte_free(pkt);
        }
        else
        {
            rte_delay_us_sleep(1);
        }
    }

    fclose(fp);
}

/**
 * 来たのを打ち返すだけ
 */
static int lcore_target(void *)
{
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    unsigned portid, nb_rx;

    portid = 1;

    while (!force_quit)
    {
        nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, BURST_SIZE);

        if (nb_rx > 0)
        {
            unsigned nb_tx = rte_eth_tx_burst(portid, 0, pkts_burst, nb_rx);
            if (nb_rx != nb_tx)
            {
                rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
            }
        }
    }
}

static int lcores_launch(void *)
{
    unsigned lcore_id = rte_lcore_id();

    switch (lcore_id)
    {
    case 0:
        lcore_main(NULL);
        break;
    case 1:
        lcore_generate_packet(NULL);
        break;
    case 2:
        lcore_protocol_stack(NULL);
        break;
#ifdef DPDK_BOUNCE
    case 3:
        lcore_target(NULL);
        break;
#endif
    default:
        break;
    }
}

int main(int argc, char *argv[])
{
    unsigned nb_ports = 0;
#ifdef DPDK_BOUNCE
    uint16_t port_mask = 0b00000011;
#else
    uint16_t port_mask = 0b00000001;
#endif
    uint16_t portid;

    force_quit = false;
    /* シグナルハンドラ */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* EALの初期化 */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* port数のカウント */
    RTE_ETH_FOREACH_DEV(portid)
    {
        if ((port_mask & (1 << portid)) == 0)
            continue;

        nb_ports++;
    }

    /* mbuf_poolの作成 */
    if ((mbuf_pool = rte_pktmbuf_pool_create(
             "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
             RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id())) == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* portの設定 */
    RTE_ETH_FOREACH_DEV(portid)
    {
        if ((port_mask & (1 << portid)) == 0)
            continue;

        if (port_init(portid, mbuf_pool, &my_macaddr) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    }

    /* ringの設定 */
    if ((rx_ring = rte_ring_create("rx_ring", 1 << 16, rte_socket_id(),
                                   RING_F_SC_DEQ | RING_F_SP_ENQ)) == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create ring\n");
    if ((tx_ring = rte_ring_create("tx_ring", 1 << 16, rte_socket_id(),
                                   RING_F_SC_DEQ | RING_F_SP_ENQ)) == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create ring\n");

    /* portの起動を待機 */
    printf("Waiting for link up\n");
    wait_linkup(port_mask);

    /* 起動 */
    rte_eal_mp_remote_launch(lcores_launch, NULL, CALL_MAIN);
    rte_eal_mp_wait_lcore();

    rte_eal_cleanup();
    return 0;
}
