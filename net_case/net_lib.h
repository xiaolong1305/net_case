#ifndef __NET_LIB_H
#define __NET_LIB_H
#include <stdint.h>
#include <stdio.h>

// output varable name
#define VNAME(name)		(#name)
#define DEBUG
#ifdef DEBUG
#define tsrn10_err(format, args...) printf(format, ##args)
#define tsrn10_dbg(format, args...) printf(format, ##args)
#define tsrn10_info(fmt, args...) printf( fmt, ##args)
#else
//#define tsr_err(format, ...)
#define tsr_err(format, args...) printf(format, ##args)
#define tsr_dbg(format, ...)
#define tsr_info(fmt, args...)
#endif

#define MAX_IFACE 2
#define MAX_DMA_LEN 2032

#define SIMULATE_HARDWARE
//reg define 
#define NF2_DMA_BASE							0x100000
//modified by xuyouqing, according to fenglei's register map
//#define NF2_DMA_BASE                      0x480000
#define DMA_RESET								(NF2_DMA_BASE + 0x0)
#define DMA_START								(NF2_DMA_BASE + 0x4)
#define DMA_INT_STATUS							(NF2_DMA_BASE + 0x8)
#define DMA_INT_MASK							(NF2_DMA_BASE + 0xc)
#define DMA_INT_CLEAR							(NF2_DMA_BASE + 0x10)
#define DMA_RX_DESC_BUFFER_BASE_ADDR_HIGH(n)    (NF2_DMA_BASE + 0x100 + (n * 0x100))
#define DMA_RX_DESC_BUFFER_BASE_ADDR_LOW(n)     (NF2_DMA_BASE + 0x104 + (n * 0x100))
#define DMA_RX_DESC_BUFFER_LEN(n)               (NF2_DMA_BASE + 0x108 + (n * 0x100))
#define DMA_RX_DESC_BUFFER_HEAD_PTR(n)          (NF2_DMA_BASE + 0x10c + (n * 0x100))
#define DMA_RX_DESC_BUFFER_TAIL_PTR(n)          (NF2_DMA_BASE + 0x110 + (n * 0x100))
#define DMA_RX_DESC_FETCH_CTRL(n)               (NF2_DMA_BASE + 0x114 + (n * 0x100))
#define DMA_RX_INT_DELAY_TIMER(n)               (NF2_DMA_BASE + 0x118 + (n * 0x100))
#define DMA_RX_INT_DELAY_PKTCNT(n)              (NF2_DMA_BASE + 0x11c + (n * 0x100))
#define DMA_TX_DESC_BUFFER_BASE_ADDR_HIGH(n)    (NF2_DMA_BASE + 0x180 + (n * 0x100))
#define DMA_TX_DESC_BUFFER_BASE_ADDR_LOW(n)     (NF2_DMA_BASE + 0x184 + (n * 0x100))
#define DMA_TX_DESC_BUFFER_LEN(n)               (NF2_DMA_BASE + 0x188 + (n * 0x100))
#define DMA_TX_DESC_BUFFER_HEAD_PTR(n)          (NF2_DMA_BASE + 0x18c + (n * 0x100))
#define DMA_TX_DESC_BUFFER_TAIL_PTR(n)          (NF2_DMA_BASE + 0x190 + (n * 0x100))
#define DMA_TX_DESC_FETCH_CTRL(n)               (NF2_DMA_BASE + 0x194 + (n * 0x100))
#define DMA_TX_INT_DELAY_TIMER(n)               (NF2_DMA_BASE + 0x198 + (n * 0x100))
#define DMA_TX_INT_DELAY_PKTCNT(n)              (NF2_DMA_BASE + 0x19c + (n * 0x100))

typedef struct simulate_dma_reg_s {
	uint32_t dma_desc_buff_base_addr_high;
	uint32_t dma_desc_buff_base_addr_low;
	uint32_t dma_desc_buff_len;
	uint32_t dma_desc_buff_head_ptr;
	uint32_t dma_desc_buff_tail_ptr;
	uint32_t dma_desc_fetch_ctrl;
	uint32_t dma_int_delay_timer;
	uint32_t dma_int_delay_pktcnt;
}simulate_dma_reg_t;
typedef struct simulate_hardware_s {
	uint32_t dma_reset;
	uint32_t dma_start;
	uint32_t dma_int_status;
	uint32_t dma_int_mask;
	uint32_t dma_int_clear;
	struct simulate_dma_reg_s dma0_rx;
	struct simulate_dma_reg_s dma0_tx;
	struct simulate_dma_reg_s dma1_rx;
	struct simulate_dma_reg_s dma1_tx;
}simulate_hardware_t;

struct nf2_packet {
	uint8_t *data;
	uint64_t dma_data_address; //data address
	struct nf2_packet *next;
	//struct net_device *dev;
	int len;
	uint32_t iface;
};
struct tx_buff {
	uint8_t *buff;
	uint64_t dma_data_address; //data address
	//struct sk_buff *skb;
	int len;
	uint32_t iface;
};
typedef struct dma_desc_s {
	uint32_t addrh; //data phy address
	uint32_t addrl; //data phy address
	uint32_t len;
	uint32_t status;
}dma_desc_t;
#define MAX_TX_BUFFS 1024
#define MAX_RX_BUFFS 1024
typedef struct port_rtx_priv_s{
	struct nf2_packet *rx_buff[MAX_TX_BUFFS]; //for each data

	uint64_t rx_ring_dma_addr;  // rx ring addr address
	uint64_t rx_buff_dma_addr;	//
	dma_desc_t *rx_ring;   // for each dma desc

	uint32_t rx_ring_len;
	uint32_t rx_ring_wp;
	uint32_t rx_ring_rd;

	struct tx_buff *tx_buff[MAX_TX_BUFFS]; 
	uint64_t tx_ring_dma_addr;
	uint64_t tx_buff_dma_addr; 
	dma_desc_t *tx_ring;

	uint32_t tx_ring_len;
	uint32_t tx_ring_wp;
	uint32_t tx_ring_rd;
}port_rtx_priv_t;

typedef struct iface_priv_s iface_priv_t;
typedef struct card_s{
	uint64_t address_base;  //pci base address
	uint8_t is_ctrl;
	iface_priv_t *iface[MAX_IFACE];
	uint32_t ifup;  // bit  xx 
	port_rtx_priv_t *rtx[MAX_IFACE];
}card_t;

struct iface_priv_s {
	card_t *card;
	uint32_t iface;  //iface number
	uint32_t send_count;
	uint32_t rece_count;
};
typedef struct msg_buff_s {
	uint8_t data[MAX_DMA_LEN];
	int length;
}msg_buff_t;
int init_dma_desc(card_t *card);
int init_card(card_t *card);
void deinit_card(card_t *card);
int card_probe(card_t *card);
void card_reset_dma(card_t *card);
int card_remove(card_t *card);
int rtx_init(card_t *card);
void rtx_deinit(card_t *card);

int net_create_rx_pool(card_t *card);
int net_destory_rx_pool(card_t *card);
int net_create_tx_pool(card_t *card);
int net_destory_tx_pool(card_t *card);
int net_open(iface_priv_t *iface);
int net_release(iface_priv_t *iface);
int net_tx(iface_priv_t *iface ,struct msg_buff_s *skb);
void net_rx(iface_priv_t *iface);
void net_intr(card_t *card);
uint32_t dma_reg_read(card_t *card, uint32_t offset);
void dma_reg_write(card_t *card, uint32_t offset, uint32_t value);
int simulate_hardware_init();
void simulate_hardware_status();
void *simulate_hardware_pthread(void *iface);
void stop_hardware_pthread();
//void *simulate_hardware(iface_priv_t *iface);
void simulate_hardware_tx_to_rx(iface_priv_t *iface);
void *simulate_intr(void *card);

#endif // !__NET_LIB_H

