#include "net_lib.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
//static varables
struct simulate_hardware_s card_hardware;
#define NUM_TX_BUFFS 512
#define NUM_RX_BUFFS 512

static int irq_start_flag;
static int hardware_pthread_flag;
static void printf_array(uint8_t *buf, int length)
{
	int i;
	for (i = 0; i < length; i++) {
		tsrn10_dbg("0x%02x ", *(buf + i));
		if ((i + 1) % 16 == 0) {
			tsrn10_dbg("\n");
		}
	}

}
void deinit_card(card_t *card)
{
	net_destory_rx_pool(card);
	net_destory_tx_pool(card);
	rtx_deinit(card);
	card_remove(card);

}


int init_card(card_t *card)
{
	int ret;
	irq_start_flag = 0;
	ret = card_probe(card);
	if (ret == 0) {
		tsrn10_dbg("card probe ok\n");
	}else {
		tsrn10_err("card probe error\n");
		goto ERR_PROBE;
	}
	
	ret = rtx_init(card);
	if (ret == 0) {
		tsrn10_dbg("rtx init ok\n");
	}else {
		tsrn10_err("rtx init error\n");
		goto ERR_RTX_INIT;
	}

	ret = net_create_tx_pool(card);
	if (ret == 0) {
		tsrn10_dbg("create tx pool ok\n");
	}else {
		tsrn10_err("create tx pool error\n");
		goto ERR_CREATE_TX_POOL;
	}

	ret = net_create_rx_pool(card);
	if (ret == 0) {
		tsrn10_dbg("create rx pool ok\n");
	}else {
		tsrn10_err("create rx pool error\n");
		goto ERR_CREATE_RX_POOL;
	}
	ret = init_dma_desc(card);
	if (ret == 0) {
		tsrn10_dbg("write to dma reg ok\n");
	}else {
		tsrn10_err("write to dma reg error\n");
		goto ERR_WRITE_REG;
	}

	return 0;
ERR_WRITE_REG:
	net_destory_rx_pool(card);
ERR_CREATE_RX_POOL:
	net_destory_tx_pool(card);
ERR_CREATE_TX_POOL:
	rtx_deinit(card);
ERR_RTX_INIT:
	card_remove(card);
ERR_PROBE:	

	return -1;
}

int init_dma_desc(card_t *card)
{
	int i,j,k;

	for (i = 0; i < MAX_IFACE; i++) {
		for (j = 0; j < card->rtx[i]->tx_ring_len; j++) {
			card->rtx[i]->tx_ring[j].addrh = (uint32_t)((card->rtx[i]->tx_buff[j]->dma_data_address) >> 32);
			card->rtx[i]->tx_ring[j].addrl = (uint32_t)((card->rtx[i]->tx_buff[j]->dma_data_address) & 0xffffffff);
			card->rtx[i]->tx_ring[j].len = MAX_DMA_LEN;
		}

		for (k = 0; k < card->rtx[i]->rx_ring_len; k++) {
			card->rtx[i]->rx_ring[k].addrh = (uint32_t)((card->rtx[i]->rx_buff[k]->dma_data_address) >> 32);
			card->rtx[i]->rx_ring[k].addrl = (uint32_t)((card->rtx[i]->rx_buff[k]->dma_data_address) & 0xffffffff);
			card->rtx[i]->rx_ring[k].len = MAX_DMA_LEN;
		}
#ifdef SIMULATE_HARDWARE

#else

	// should copy dma desc to memory
#endif 
	//write all info to hardware
		dma_reg_write(card, DMA_TX_DESC_BUFFER_BASE_ADDR_HIGH(i), card->rtx[i]->tx_ring_dma_addr >> 32);
		dma_reg_write(card, DMA_TX_DESC_BUFFER_BASE_ADDR_LOW(i), card->rtx[i]->tx_ring_dma_addr & 0xffffffff);
		dma_reg_write(card, DMA_TX_DESC_BUFFER_LEN(i), card->rtx[i]->tx_ring_len);
		dma_reg_write(card, DMA_TX_DESC_FETCH_CTRL(i), 0x200010);
		dma_reg_write(card, DMA_TX_INT_DELAY_TIMER(i), 125000);
		dma_reg_write(card, DMA_TX_INT_DELAY_PKTCNT(i), 16);
		dma_reg_write(card, DMA_TX_DESC_BUFFER_TAIL_PTR(i), 0x0);

		dma_reg_write(card, DMA_RX_DESC_BUFFER_BASE_ADDR_HIGH(i), card->rtx[i]->rx_ring_dma_addr >> 32);
		dma_reg_write(card, DMA_RX_DESC_BUFFER_BASE_ADDR_LOW(i), card->rtx[i]->rx_ring_dma_addr & 0xffffffff);
		dma_reg_write(card, DMA_RX_DESC_BUFFER_LEN(i), card->rtx[i]->rx_ring_len);
		dma_reg_write(card, DMA_RX_DESC_FETCH_CTRL(i), 0x200010);
		dma_reg_write(card, DMA_RX_INT_DELAY_TIMER(i), 125000);
		dma_reg_write(card, DMA_RX_INT_DELAY_PKTCNT(i), 16);
		dma_reg_write(card, DMA_RX_DESC_BUFFER_TAIL_PTR(i), card->rtx[i]->rx_ring_len -1);

		dma_reg_write(card, DMA_INT_MASK, 0x00);
	}
	
	return 0;
}

int card_probe(card_t *card)
{
	int ret;
#ifdef SIMULATE_HARDWARE	
	card->address_base = 0x00;
#else
	// pcie base address
	card->address_base = 0x10000000;
#endif
	card->ifup = 0;
	card->is_ctrl = 0;

	card_reset_dma(card);
	ret = rtx_init(card);

	return 0;
}
void rtx_deinit(card_t *card)
{
	port_rtx_priv_t *rtx[MAX_IFACE];
	int i;
	for (i = 0; i < MAX_IFACE; i++) {

		rtx[i] = card->rtx[i];
#ifdef SIMULATE_HARDWARE
		if (rtx[i]->rx_ring != NULL) {
			free(rtx[i]->rx_ring);
		}
		if (rtx[i]->tx_ring != NULL) {
			free(rtx[i]->tx_ring);
		}
		if (rtx[i] != NULL) {
			free(rtx[i]);
		}
#else
		//define own
// release memory

#endif
	}

}
int net_create_rx_pool(card_t *card)
{
	int i ,j;
	struct nf2_packet *rx_buff[NUM_TX_BUFFS];
	for (i = 0; i < MAX_IFACE; i++) {
		//memory alloc for each tx_buff
		for (j = 0; j < NUM_TX_BUFFS; j++) {
#ifdef SIMULATE_HARDWARE
			rx_buff[j] = (struct nf2_packet *)malloc(sizeof(struct nf2_packet));
			rx_buff[j]->data = (uint8_t *)malloc(MAX_DMA_LEN);
			rx_buff[j]->dma_data_address = (uint64_t)rx_buff[j]->data;
			rx_buff[j]->iface = i;
			rx_buff[j]->len = 0;
			//link the rx ring
			if (j != (card->rtx[i]->rx_ring_len - 1)) {
				rx_buff[j]->next = rx_buff[j + 1];
			}
			else {
				rx_buff[j]->next = rx_buff[0];
			}
#else

#endif
		card->rtx[i]->rx_buff[j] = rx_buff[j];
		}
	}

	return 0;
}

int net_destory_rx_pool(card_t *card)
{
	int i, j;
	for (i = 0; i < MAX_IFACE; i++) {
		//memory alloc for each tx_buff
		for (j = 0; j < NUM_TX_BUFFS; j++) {
			if (card->rtx[i]->rx_buff[j] != NULL) {
				if (card->rtx[i]->rx_buff[j]->data != NULL) {
					free(card->rtx[i]->rx_buff[j]->data);
				}
				free(card->rtx[i]->rx_buff[j]);
			}

		}
	}
	return 0;

}
int net_create_tx_pool(card_t *card)
{
	int i ,j;
	struct tx_buff *tx_buff[NUM_TX_BUFFS];
	for (i = 0; i < MAX_IFACE; i++) {
		//memory alloc for each tx_buff
		for (j = 0; j < NUM_TX_BUFFS; j++) {
#ifdef SIMULATE_HARDWARE
			tx_buff[j] = (struct tx_buff *)malloc(sizeof(struct tx_buff));
			if (tx_buff[j] == NULL) {
				goto ERR_TX_BUFF_ALLOC;
			}
			tx_buff[j]->buff = (uint8_t *)malloc(MAX_DMA_LEN);
			if (tx_buff[j]->buff == NULL) {
				goto ERR_TX_BUFF_ALLOC;
			}
			tx_buff[j]->dma_data_address = (uint64_t)tx_buff[j]->buff;
			tx_buff[j]->iface = i;
			tx_buff[j]->len = 0;
#else

#endif
			card->rtx[i]->tx_buff[j] = tx_buff[j];
		}
	}
	return 0;
ERR_TX_BUFF_ALLOC:
	net_destory_tx_pool(card);
	return -1;
}
int net_destory_tx_pool(card_t *card)
{
	int i, j;
	for (i = 0; i < MAX_IFACE; i++) {
		//memory alloc for each tx_buff
		for (j = 0; j < NUM_TX_BUFFS; j++) {
			if (card->rtx[i]->tx_buff[j] != NULL) {
				if (card->rtx[i]->tx_buff[j]->buff != NULL) {
					free(card->rtx[i]->tx_buff[j]->buff);
				}
				free(card->rtx[i]->tx_buff[j]);
			}

		}
	}
	return 0;
}

int rtx_init(card_t *card)
{
	port_rtx_priv_t *rtx[MAX_IFACE];
	int i;
	int ret;
	// malloc for rtx
	for (i = 0; i < MAX_IFACE; i++) {

		rtx[i] = (port_rtx_priv_t *)malloc(sizeof(port_rtx_priv_t));
		if (rtx[i] == NULL) {
			tsrn10_err("fail to alloc memory\n");
			ret = -1;
			goto ERR_FREE_RTX;
		}
		rtx[i]->rx_ring_len = NUM_RX_BUFFS;
		rtx[i]->rx_ring_rd = NUM_RX_BUFFS - 1;
		rtx[i]->rx_ring_wp = 0;

		rtx[i]->tx_ring_len = NUM_TX_BUFFS;
		rtx[i]->tx_ring_rd = 0;
		rtx[i]->tx_ring_wp = 0;
#ifdef SIMULATE_HARDWARE
		rtx[i]->rx_ring = (dma_desc_t *)malloc(sizeof(dma_desc_t)*NUM_RX_BUFFS);
		rtx[i]->rx_ring_dma_addr = (uint64_t)rtx[i]->rx_ring;
		if (rtx[i]->rx_ring == NULL) {
			ret = -1;
			goto ERR_FREE_RING;
		}
		rtx[i]->tx_ring = (dma_desc_t *)malloc(sizeof(dma_desc_t)*NUM_TX_BUFFS);
		rtx[i]->tx_ring_dma_addr = (uint64_t)rtx[i]->tx_ring;
		if (rtx[i]->rx_ring == NULL) {
			ret = -1;
			goto ERR_FREE_RING;
		}
#else
//should set rx_ring_dma_addr and tx_ring_dma_addr
// such as request memory rx_ring and tx_ring not used
//

#endif
		card->rtx[i] = rtx[i];
	}
		return 0;
ERR_FREE_RING:
	for (i = 0; i < MAX_IFACE; i++)
	{
		if (rtx[i]->rx_ring != NULL) {
			free(rtx[i]->rx_ring);
		}
		if (rtx[i]->tx_ring != NULL) {
			free(rtx[i]->tx_ring);
		}
	}

ERR_FREE_RTX:
	for (i = 0; i < MAX_IFACE; i++)
	{
		if (rtx[i] != NULL) {
			free(rtx[i]);
		}
	}
	return ret;
}
void card_reset_dma(card_t *card)
{
	uint32_t intmask;

	intmask = dma_reg_read(card, DMA_INT_MASK);
	dma_reg_write(card, DMA_RESET, 1);
	dma_reg_write(card, DMA_INT_MASK,intmask);
}

int card_remove(card_t *card)
{


	return 0;
}



int net_open(iface_priv_t *iface_port)
{
// set dma up 
	int channel_enable;
	int eth = iface_port->iface;
	card_t *card = iface_port->card;
// set card up status
	card->ifup |= 1 << eth;
// start tx and rx dma 
	channel_enable = dma_reg_read(card, DMA_START);
	channel_enable = channel_enable | (0x10001) << eth;
	dma_reg_write(card, DMA_START, channel_enable);
// read head to rx_ring_rd
// set rx tail
	card->rtx[eth]->rx_ring_rd = dma_reg_read(card,DMA_RX_DESC_BUFFER_HEAD_PTR(eth));
#ifdef SIMULATE_HARDWARE
	//set head
	dma_reg_write(card, DMA_RX_DESC_BUFFER_TAIL_PTR(eth), \
		(card->rtx[eth]->rx_ring_rd));

#else
	//hardware request to do this init
	dma_reg_write(card, DMA_RX_DESC_BUFFER_TAIL_PTR(eth), \
		(card->rtx[eth]->rx_ring_rd + card->rtx[eth]->rx_ring_len - 1) % (card->rtx[eth]->rx_ring_len));
#endif 
	// set tx tail
	card->rtx[eth]->rx_ring_wp = dma_reg_read(card,DMA_TX_DESC_BUFFER_HEAD_PTR(eth));
	dma_reg_write(card, DMA_TX_DESC_BUFFER_TAIL_PTR(eth), card->rtx[eth]->rx_ring_wp);
	// set irq
	irq_start_flag = 1;

	return 1;
}
int net_release(iface_priv_t *iface_port)
{
	int channel_enable;
	int eth = iface_port->iface;
	card_t *card = iface_port->card;

	// update ifup flag
	card->ifup &= ~(1 << eth);

	//close dma
	channel_enable = dma_reg_read(card, DMA_START);
	channel_enable = channel_enable &(~((0x10001) << eth));
	dma_reg_write(card, DMA_START, channel_enable);

	if (!card->ifup) {
		irq_start_flag = 0;
	}
	return 1;
}
int net_tx(iface_priv_t *iface, struct msg_buff_s *skb)
{
	card_t *card = iface->card;
	int eth = iface->iface;
	int tx_ring_head = card->rtx[eth]->tx_ring_rd;
	int tx_ring_tail = card->rtx[eth]->tx_ring_wp;
	dma_desc_t *tx_ring_base = card->rtx[eth]->tx_ring;
	struct tx_buff **tx_buff_base = card->rtx[eth]->tx_buff;

	if (tx_ring_head == ((tx_ring_tail + 1)&(NUM_TX_BUFFS - 1))) {

		tsrn10_dbg("drop one packet\n");
		return -1;
	}
	else {
		tx_ring_base[tx_ring_tail].len = skb->length;
		tx_buff_base[tx_ring_tail]->len = skb->length;
#ifdef SIMULATE_HARDWARE
		memcpy(tx_buff_base[tx_ring_tail]->buff,skb->data, skb->length);
		//tsrn10_dbg("***%08x\n", tx_buff_base[tx_ring_tail]->dma_data_address);
#else
		

#endif 
		tx_ring_tail = (tx_ring_tail + 1)&(NUM_TX_BUFFS - 1);
		card->rtx[eth]->tx_ring_wp = tx_ring_tail;
		iface->send_count++;
		dma_reg_write(card, DMA_TX_DESC_BUFFER_TAIL_PTR(eth), tx_ring_tail);

	}

	return 1;
}
void net_rx(iface_priv_t *iface)
{
	card_t *card = iface->card;
	int eth = iface->iface;
	int rx_ring_tail = card->rtx[eth]->rx_ring_rd; 
	int rx_ring_head = card->rtx[eth]->rx_ring_wp; //update when rx int come
	dma_desc_t *rx_ring_base = card->rtx[eth]->rx_ring;
	struct nf2_packet **rx_buff_base = card->rtx[eth]->rx_buff;
	int rx_pkt_len;

	while (rx_ring_head != rx_ring_tail) {
		rx_pkt_len = rx_ring_base[rx_ring_tail].len;
#ifdef SIMULATE_HARDWARE
		//printf the received msg 
		tsrn10_dbg("rx msg:\n");
		printf_array(rx_buff_base[rx_ring_tail]->data, rx_pkt_len);
		//printf_array(card->rtx[eth]->rx_buff[rx_ring_tail]->data, rx_pkt_len);
		//memcpy(skb->data, card->rtx[eth]->rx_buff[rx_ring_tail]->data, rx_pkt_len);
#else

#endif
//		skb->length = rx_pkt_len;
		rx_ring_tail = (rx_ring_tail + 1)&(NUM_RX_BUFFS - 1);
	}
	card->rtx[eth]->rx_ring_rd = rx_ring_tail;
	dma_reg_write(card, DMA_RX_DESC_BUFFER_TAIL_PTR(eth), card->rtx[eth]->rx_ring_rd);
	iface->rece_count++;
}
//simulate interupt
void *simulate_intr(void *card)
{
	card_t *card_temp = (card_t *)card;
	//should start the irq
	irq_start_flag = 1;
	while (irq_start_flag == 1) {
		tsrn10_dbg("in the intr func\n");
		net_intr(card_temp);
		usleep(10);
	}
	pthread_exit(NULL);

}
void net_intr(card_t *card) 
{
	uint32_t int_mask = 0;
	uint32_t status = 0;
	uint32_t status_temp;
	int_mask = dma_reg_read(card, DMA_INT_MASK);
	int rx_eth = -1;
	int tx_eth = -1;

	status = dma_reg_read(card, DMA_INT_STATUS);
	if (status) {
		tsrn10_dbg("intr mask 0x%08x\n", int_mask);
		tsrn10_dbg("intr status 0x%08x\n", status);
	}
	status = status & (~int_mask);
	status_temp = status;

	while (status_temp) {
		if (status_temp & 0x01) {
			rx_eth = 0;
			status_temp = status_temp & (~(0x01));
		}
		else if (status_temp & 0x02) {
			rx_eth = 1;
			status_temp = status_temp & (~(0x02));
		}

		if (status_temp & 0x10000) {
			tx_eth = 0;
			status_temp = status_temp & (~(0x10000));
		}
		else if (status_temp & 0x20000) {
			tx_eth = 1;
			status_temp = status_temp & (~(0x20000));
		}
		//handle rx interrupt
		if (rx_eth != -1) {
			tsrn10_dbg("intr dma rx %d\n", rx_eth);
			card->rtx[rx_eth]->rx_ring_wp = dma_reg_read(card, DMA_RX_DESC_BUFFER_HEAD_PTR(rx_eth));
			net_rx(card->iface[rx_eth]);
			rx_eth = -1;
		}

		//handle tx interrupt
		if (tx_eth != -1) {
			tsrn10_dbg("intr dma tx %d\n", tx_eth);
			card->rtx[tx_eth]->tx_ring_rd = dma_reg_read(card, DMA_TX_DESC_BUFFER_HEAD_PTR(tx_eth));
			tx_eth = -1;
		}
	}
	if (status) {
		dma_reg_write(card, DMA_INT_CLEAR, status);
	}

}


uint32_t dma_reg_read(card_t *card, uint32_t offset)
{
	uint32_t reg_value;
#ifdef SIMULATE_HARDWARE
	switch (offset)
	{
	case DMA_RESET:
		reg_value = card_hardware.dma_reset;
		break;
	case DMA_START:
		reg_value = card_hardware.dma_start;
		break;
	case DMA_INT_STATUS:
		reg_value = card_hardware.dma_int_status;
		break;
	case DMA_INT_MASK:
		reg_value = card_hardware.dma_int_mask;
		break;
	case DMA_INT_CLEAR:
		reg_value = card_hardware.dma_int_clear;
		break;
	case DMA_RX_DESC_BUFFER_BASE_ADDR_HIGH(0):
		reg_value = card_hardware.dma0_rx.dma_desc_buff_base_addr_high;
		break;
	case DMA_RX_DESC_BUFFER_BASE_ADDR_LOW(0):
		reg_value = card_hardware.dma0_rx.dma_desc_buff_base_addr_low;
		break;
	case DMA_RX_DESC_BUFFER_LEN(0):
		reg_value = card_hardware.dma0_rx.dma_desc_buff_len;
		break;
	case DMA_RX_DESC_BUFFER_HEAD_PTR(0):
		reg_value = card_hardware.dma0_rx.dma_desc_buff_head_ptr;
		break;
	case DMA_RX_DESC_BUFFER_TAIL_PTR(0):
		reg_value = card_hardware.dma0_rx.dma_desc_buff_tail_ptr;
		break;
	case DMA_RX_DESC_FETCH_CTRL(0):
		reg_value = card_hardware.dma0_rx.dma_desc_fetch_ctrl;
		break;
	case DMA_RX_INT_DELAY_TIMER(0):
		reg_value = card_hardware.dma0_rx.dma_int_delay_timer;
		break;
	case DMA_RX_INT_DELAY_PKTCNT(0):
		reg_value = card_hardware.dma0_rx.dma_int_delay_pktcnt;
		break;


	case DMA_TX_DESC_BUFFER_BASE_ADDR_HIGH(0):
		reg_value = card_hardware.dma0_tx.dma_desc_buff_base_addr_high;
		break;
	case DMA_TX_DESC_BUFFER_BASE_ADDR_LOW(0):
		reg_value = card_hardware.dma0_tx.dma_desc_buff_base_addr_low;
		break;
	case DMA_TX_DESC_BUFFER_LEN(0):
		reg_value = card_hardware.dma0_tx.dma_desc_buff_len;
		break;
	case DMA_TX_DESC_BUFFER_HEAD_PTR(0):
		reg_value = card_hardware.dma0_tx.dma_desc_buff_head_ptr;
		break;
	case DMA_TX_DESC_BUFFER_TAIL_PTR(0):
		reg_value = card_hardware.dma0_tx.dma_desc_buff_tail_ptr;
		break;
	case DMA_TX_DESC_FETCH_CTRL(0):
		reg_value = card_hardware.dma0_tx.dma_desc_fetch_ctrl;
		break;
	case DMA_TX_INT_DELAY_TIMER(0):
		reg_value = card_hardware.dma0_tx.dma_int_delay_timer;
		break;
	case DMA_TX_INT_DELAY_PKTCNT(0):
		reg_value = card_hardware.dma0_tx.dma_int_delay_pktcnt;
		break;

	case DMA_RX_DESC_BUFFER_BASE_ADDR_HIGH(1):
		reg_value = card_hardware.dma1_rx.dma_desc_buff_base_addr_high;
		break;
	case DMA_RX_DESC_BUFFER_BASE_ADDR_LOW(1):
		reg_value = card_hardware.dma1_rx.dma_desc_buff_base_addr_low;
		break;
	case DMA_RX_DESC_BUFFER_LEN(1):
		reg_value = card_hardware.dma1_rx.dma_desc_buff_len;
		break;
	case DMA_RX_DESC_BUFFER_HEAD_PTR(1):
		reg_value = card_hardware.dma1_rx.dma_desc_buff_head_ptr;
		break;
	case DMA_RX_DESC_BUFFER_TAIL_PTR(1):
		reg_value = card_hardware.dma1_rx.dma_desc_buff_tail_ptr;
		break;
	case DMA_RX_DESC_FETCH_CTRL(1):
		reg_value = card_hardware.dma1_rx.dma_desc_fetch_ctrl;
		break;
	case DMA_RX_INT_DELAY_TIMER(1):
		reg_value = card_hardware.dma1_rx.dma_int_delay_timer;
		break;
	case DMA_RX_INT_DELAY_PKTCNT(1):
		reg_value = card_hardware.dma1_rx.dma_int_delay_pktcnt;
		break;


	case DMA_TX_DESC_BUFFER_BASE_ADDR_HIGH(1):
		reg_value = card_hardware.dma1_tx.dma_desc_buff_base_addr_high;
		break;
	case DMA_TX_DESC_BUFFER_BASE_ADDR_LOW(1):
		reg_value = card_hardware.dma1_tx.dma_desc_buff_base_addr_low;
		break;
	case DMA_TX_DESC_BUFFER_LEN(1):
		reg_value = card_hardware.dma1_tx.dma_desc_buff_len;
		break;
	case DMA_TX_DESC_BUFFER_HEAD_PTR(1):
		reg_value = card_hardware.dma1_tx.dma_desc_buff_head_ptr;
		break;
	case DMA_TX_DESC_BUFFER_TAIL_PTR(1):
		reg_value = card_hardware.dma1_tx.dma_desc_buff_tail_ptr;
		break;
	case DMA_TX_DESC_FETCH_CTRL(1):
		reg_value = card_hardware.dma1_tx.dma_desc_fetch_ctrl;
		break;
	case DMA_TX_INT_DELAY_TIMER(1):
		reg_value = card_hardware.dma1_tx.dma_int_delay_timer;
		break;
	case DMA_TX_INT_DELAY_PKTCNT(1):
		reg_value = card_hardware.dma1_tx.dma_int_delay_pktcnt;
		break;
	default:
		tsrn10_err("reg offset error\n");
	}
	tsrn10_dbg("read reg 0x%08x: 0x%08x\n", offset,reg_value);
	return reg_value;

#else
	//use real bar read from hardware
	// card->address + offset
#endif

}
void dma_reg_write(card_t *card, uint32_t offset, uint32_t value)
{
	tsrn10_dbg("write 0x%08x to reg 0x%08x\n", value, offset);
#ifdef SIMULATE_HARDWARE
	switch (offset)
	{
	case DMA_RESET:
		card_hardware.dma_reset = value;
		break;
	case DMA_START:
		card_hardware.dma_start = value;
		break;
	case DMA_INT_STATUS:
		card_hardware.dma_int_status = value;
		break;
	case DMA_INT_MASK:
		card_hardware.dma_int_mask = value;
		break;
	case DMA_INT_CLEAR:
		card_hardware.dma_int_clear = value;
		break;
	case DMA_RX_DESC_BUFFER_BASE_ADDR_HIGH(0):
		card_hardware.dma0_rx.dma_desc_buff_base_addr_high = value;
		break;
	case DMA_RX_DESC_BUFFER_BASE_ADDR_LOW(0):
		card_hardware.dma0_rx.dma_desc_buff_base_addr_low = value;
		break;
	case DMA_RX_DESC_BUFFER_LEN(0):
		card_hardware.dma0_rx.dma_desc_buff_len = value;
		break;
	case DMA_RX_DESC_BUFFER_HEAD_PTR(0):
		card_hardware.dma0_rx.dma_desc_buff_head_ptr = value;
		break;
	case DMA_RX_DESC_BUFFER_TAIL_PTR(0):
		card_hardware.dma0_rx.dma_desc_buff_tail_ptr = value;
		break;
	case DMA_RX_DESC_FETCH_CTRL(0):
		card_hardware.dma0_rx.dma_desc_fetch_ctrl = value;
		break;
	case DMA_RX_INT_DELAY_TIMER(0):
		card_hardware.dma0_rx.dma_int_delay_timer = value;
		break;
	case DMA_RX_INT_DELAY_PKTCNT(0):
		card_hardware.dma0_rx.dma_int_delay_pktcnt = value;
		break;


	case DMA_TX_DESC_BUFFER_BASE_ADDR_HIGH(0):
		card_hardware.dma0_tx.dma_desc_buff_base_addr_high = value;
		break;
	case DMA_TX_DESC_BUFFER_BASE_ADDR_LOW(0):
		card_hardware.dma0_tx.dma_desc_buff_base_addr_low = value;
		break;
	case DMA_TX_DESC_BUFFER_LEN(0):
		card_hardware.dma0_tx.dma_desc_buff_len = value;
		break;
	case DMA_TX_DESC_BUFFER_HEAD_PTR(0):
		card_hardware.dma0_tx.dma_desc_buff_head_ptr = value;
		break;
	case DMA_TX_DESC_BUFFER_TAIL_PTR(0):
		card_hardware.dma0_tx.dma_desc_buff_tail_ptr = value;
		break;
	case DMA_TX_DESC_FETCH_CTRL(0):
		card_hardware.dma0_tx.dma_desc_fetch_ctrl = value;
		break;
	case DMA_TX_INT_DELAY_TIMER(0):
		card_hardware.dma0_tx.dma_int_delay_timer = value;
		break;
	case DMA_TX_INT_DELAY_PKTCNT(0):
		card_hardware.dma0_tx.dma_int_delay_pktcnt = value;
		break;

	case DMA_RX_DESC_BUFFER_BASE_ADDR_HIGH(1):
		card_hardware.dma1_rx.dma_desc_buff_base_addr_high = value;
		break;
	case DMA_RX_DESC_BUFFER_BASE_ADDR_LOW(1):
		card_hardware.dma1_rx.dma_desc_buff_base_addr_low = value;
		break;
	case DMA_RX_DESC_BUFFER_LEN(1):
		card_hardware.dma1_rx.dma_desc_buff_len = value;
		break;
	case DMA_RX_DESC_BUFFER_HEAD_PTR(1):
		card_hardware.dma1_rx.dma_desc_buff_head_ptr = value;
		break;
	case DMA_RX_DESC_BUFFER_TAIL_PTR(1):
		card_hardware.dma1_rx.dma_desc_buff_tail_ptr = value;
		break;
	case DMA_RX_DESC_FETCH_CTRL(1):
		card_hardware.dma1_rx.dma_desc_fetch_ctrl = value;
		break;
	case DMA_RX_INT_DELAY_TIMER(1):
		card_hardware.dma1_rx.dma_int_delay_timer = value;
		break;
	case DMA_RX_INT_DELAY_PKTCNT(1):
		card_hardware.dma1_rx.dma_int_delay_pktcnt = value;
		break;


	case DMA_TX_DESC_BUFFER_BASE_ADDR_HIGH(1):
		card_hardware.dma1_tx.dma_desc_buff_base_addr_high = value;
		break;
	case DMA_TX_DESC_BUFFER_BASE_ADDR_LOW(1):
		card_hardware.dma1_tx.dma_desc_buff_base_addr_low = value;
		break;
	case DMA_TX_DESC_BUFFER_LEN(1):
		card_hardware.dma1_tx.dma_desc_buff_len = value;
		break;
	case DMA_TX_DESC_BUFFER_HEAD_PTR(1):
		card_hardware.dma1_tx.dma_desc_buff_head_ptr = value;
		break;
	case DMA_TX_DESC_BUFFER_TAIL_PTR(1):
		card_hardware.dma1_tx.dma_desc_buff_tail_ptr = value;
		break;
	case DMA_TX_DESC_FETCH_CTRL(1):
		card_hardware.dma1_tx.dma_desc_fetch_ctrl = value;
		break;
	case DMA_TX_INT_DELAY_TIMER(1):
		card_hardware.dma1_tx.dma_int_delay_timer = value;
		break;
	case DMA_TX_INT_DELAY_PKTCNT(1):
		card_hardware.dma1_tx.dma_int_delay_pktcnt = value;
		break;
	default:
		tsrn10_err("reg offset error\n");
	}

#else
	dma_reg_write(card, DMA_RX_DESC_BUFFER_TAIL_PTR(eth), \
		(card->rtx[eth]->rx_ring_rd + card->rtx[eth]->rx_ring_len - 1) % (card->rtx[eth]->rx_ring_len));
	//use real bar write to hardware
	tsrn10_dbg("write 0x%08x to reg 0x%08x\n", value, offset);
#endif

}
void stop_hardware_pthread()
{
	hardware_pthread_flag = 0;

}
// simulate hardware pthread
void *simulate_hardware_pthread(void *iface)
{

	iface_priv_t *iface_temp = (iface_priv_t *)iface;
	hardware_pthread_flag = 1;
	while (hardware_pthread_flag == 1)
	{
		simulate_hardware_tx_to_rx(iface_temp);
	
		usleep(10);

	}
	pthread_exit(NULL);

}

/*
void simulate_hardware(iface_priv_t *iface)
{
	card_t *card = iface->card;
	int eth = iface->iface;
	dma_desc_t *tx_ring_base = card->rtx[eth]->tx_ring;
	struct tx_buff **tx_buff_base = card->rtx[eth]->tx_buff;
	dma_desc_t *rx_ring_base = card->rtx[eth]->rx_ring;
	struct nf2_packet **rx_buff_base = card->rtx[eth]->rx_buff;
	uint8_t msg[MAX_DMA_LEN];
	int pkt_len;
	uint32_t tx_ring_head;
	uint32_t tx_ring_tail;
	uint32_t rx_ring_head;
	uint32_t rx_ring_tail;
	memset(msg, 0x00, MAX_DMA_LEN);
	// eth 0 
	if (eth == 0) {
		tx_ring_head = card_hardware.dma0_tx.dma_desc_buff_head_ptr;
		tx_ring_tail = card_hardware.dma0_tx.dma_desc_buff_tail_ptr;
		rx_ring_head = card_hardware.dma0_rx.dma_desc_buff_head_ptr;
		rx_ring_tail = card_hardware.dma0_rx.dma_desc_buff_tail_ptr;
		// there is packet in tx buff
		if (tx_ring_head != tx_ring_tail) {
			pkt_len = tx_ring_base[tx_ring_head].len;
			memcpy(msg, tx_buff_base[tx_ring_head]->buff, pkt_len);
			tsrn10_dbg("hardware:tx len is %d,data is: \n", pkt_len);
			//printf_array(msg, pkt_len);
			//add head
			tx_ring_head = (tx_ring_head + 1) &(card_hardware.dma0_tx.dma_desc_buff_len - 1);
			card_hardware.dma0_tx.dma_desc_buff_head_ptr = tx_ring_head;
			//set int status
			card_hardware.dma_int_status |= 1 << eth;
			
			// copy to rx_buff
			// rx ring buff is not full
			if (((rx_ring_head + 1)&(card_hardware.dma0_rx.dma_desc_buff_len-1)) != (rx_ring_tail))
			{
				memcpy(rx_buff_base[rx_ring_head]->data, msg, pkt_len);
				rx_ring_head = (rx_ring_head + 1)&(card_hardware.dma0_rx.dma_desc_buff_len - 1);
				card_hardware.dma0_rx.dma_desc_buff_head_ptr = rx_ring_head;
				// set int status
				card_hardware.dma_int_status |= 0x10000 << eth;

			}

		}
	}
	else if (eth == 1) {
		tx_ring_head = card_hardware.dma1_tx.dma_desc_buff_head_ptr;
		tx_ring_tail = card_hardware.dma1_tx.dma_desc_buff_tail_ptr;
		rx_ring_head = card_hardware.dma0_rx.dma_desc_buff_head_ptr;
		rx_ring_tail = card_hardware.dma0_rx.dma_desc_buff_tail_ptr;

		// there is packet in tx buff
		if (tx_ring_head != tx_ring_tail) {
			pkt_len = tx_ring_base[tx_ring_head].len;
			memcpy(msg, tx_buff_base[tx_ring_head]->buff, pkt_len);
			tsrn10_dbg("hardware:tx len is %d,data is: \n", pkt_len);
			//printf_array(msg, pkt_len);
			//add head
			tx_ring_head = (tx_ring_head + 1) &(card_hardware.dma1_tx.dma_desc_buff_len - 1);
			card_hardware.dma1_tx.dma_desc_buff_head_ptr = tx_ring_head;
			//set int status
			card_hardware.dma_int_status |= 1 << eth;
			
			// copy to rx_buff
			if (((rx_ring_head + 1)&(card_hardware.dma0_rx.dma_desc_buff_len - 1)) != (rx_ring_tail))
			{
				memcpy(rx_buff_base[rx_ring_head]->data, msg, pkt_len);
				rx_ring_head = (rx_ring_head + 1)&(card_hardware.dma1_rx.dma_desc_buff_len - 1);
				card_hardware.dma1_rx.dma_desc_buff_head_ptr = rx_ring_head;
				// set int status
				card_hardware.dma_int_status |= 0x10000 << eth;
			}

		}

	}

}*/
// put tx_buff to rx_buff 
void simulate_hardware_tx_to_rx(iface_priv_t *iface)
{
	card_t *card = iface->card;
	int eth = iface->iface;
	dma_desc_t *tx_ring_base = card->rtx[eth]->tx_ring;
	struct tx_buff **tx_buff_base = card->rtx[eth]->tx_buff;
	dma_desc_t *rx_ring_base = card->rtx[eth]->rx_ring;
	struct nf2_packet **rx_buff_base = card->rtx[eth]->rx_buff;
	uint8_t msg[MAX_DMA_LEN];
	int pkt_len;
	uint32_t tx_ring_head;
	uint32_t tx_ring_tail;
	uint32_t rx_ring_head;
	uint32_t rx_ring_tail;
	memset(msg, 0x00, MAX_DMA_LEN);
	// eth 0 
	if (eth == 0) {
		tx_ring_head = card_hardware.dma0_tx.dma_desc_buff_head_ptr;
		tx_ring_tail = card_hardware.dma0_tx.dma_desc_buff_tail_ptr;
		rx_ring_head = card_hardware.dma0_rx.dma_desc_buff_head_ptr;
		rx_ring_tail = card_hardware.dma0_rx.dma_desc_buff_tail_ptr;
		// there is packet in tx buff
		if (tx_ring_head != tx_ring_tail) {
			pkt_len = tx_ring_base[tx_ring_head].len;
			memcpy(msg, tx_buff_base[tx_ring_head]->buff, pkt_len);
			tsrn10_dbg("hardware:tx len is %d,data is: \n", pkt_len);
			//printf_array(msg, pkt_len);
			//add head
			tx_ring_head = (tx_ring_head + 1) &(card_hardware.dma0_tx.dma_desc_buff_len - 1);
			card_hardware.dma0_tx.dma_desc_buff_head_ptr = tx_ring_head;
			//set int status
			card_hardware.dma_int_status |= 1 << eth;
			
			// copy to rx_buff
			// rx ring buff is not full
			if (((rx_ring_head + 1)&(card_hardware.dma0_rx.dma_desc_buff_len-1)) != (rx_ring_tail))
			{
				memcpy(rx_buff_base[rx_ring_head]->data, msg, pkt_len);
				rx_ring_head = (rx_ring_head + 1)&(card_hardware.dma0_rx.dma_desc_buff_len - 1);
				card_hardware.dma0_rx.dma_desc_buff_head_ptr = rx_ring_head;
				// set int status
				card_hardware.dma_int_status |= 0x10000 << eth;

			}

		}
	}
	else if (eth == 1) {
		tx_ring_head = card_hardware.dma1_tx.dma_desc_buff_head_ptr;
		tx_ring_tail = card_hardware.dma1_tx.dma_desc_buff_tail_ptr;
		rx_ring_head = card_hardware.dma0_rx.dma_desc_buff_head_ptr;
		rx_ring_tail = card_hardware.dma0_rx.dma_desc_buff_tail_ptr;

		// there is packet in tx buff
		if (tx_ring_head != tx_ring_tail) {
			pkt_len = tx_ring_base[tx_ring_head].len;
			memcpy(msg, tx_buff_base[tx_ring_head]->buff, pkt_len);
			tsrn10_dbg("hardware:tx len is %d,data is: \n", pkt_len);
			//printf_array(msg, pkt_len);
			//add head
			tx_ring_head = (tx_ring_head + 1) &(card_hardware.dma1_tx.dma_desc_buff_len - 1);
			card_hardware.dma1_tx.dma_desc_buff_head_ptr = tx_ring_head;
			//set int status
			card_hardware.dma_int_status |= 1 << eth;
			
			// copy to rx_buff
			if (((rx_ring_head + 1)&(card_hardware.dma0_rx.dma_desc_buff_len - 1)) != (rx_ring_tail))
			{
				memcpy(rx_buff_base[rx_ring_head]->data, msg, pkt_len);
				rx_ring_head = (rx_ring_head + 1)&(card_hardware.dma1_rx.dma_desc_buff_len - 1);
				card_hardware.dma1_rx.dma_desc_buff_head_ptr = rx_ring_head;
				// set int status
				card_hardware.dma_int_status |= 0x10000 << eth;
			}

		}

	}

}

int simulate_hardware_init()
{
	//init the simulate hardware  
	// set all reg to 0x00
	memset(&card_hardware, 0x00, sizeof(struct simulate_dma_reg_s));
}
//printf all reg
void simulate_hardware_status()
{
#ifdef SIMULATE_HARDWARE
	struct simulate_dma_reg_s *dma_rx;
	tsrn10_dbg("hardware status:\n");
	tsrn10_dbg("%s:0x%08x\n", VNAME(card_hardware.dma_reset), card_hardware.dma_reset);
	tsrn10_dbg("%s:0x%08x\n", VNAME(card_hardware.dma_start), card_hardware.dma_start);
	tsrn10_dbg("%s:0x%08x\n", VNAME(card_hardware.dma_int_status), card_hardware.dma_int_status);
	tsrn10_dbg("%s:0x%08x\n", VNAME(card_hardware.dma_int_mask), card_hardware.dma_int_mask);
	tsrn10_dbg("%s:0x%08x\n", VNAME(card_hardware.dma_int_clear), card_hardware.dma_int_clear);

	dma_rx = &card_hardware.dma0_rx;
	tsrn10_dbg("dma0_rx status:\n");
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_high), dma_rx->dma_desc_buff_base_addr_high);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_low), dma_rx->dma_desc_buff_base_addr_low);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_len), dma_rx->dma_desc_buff_len);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_head_ptr), dma_rx->dma_desc_buff_head_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_tail_ptr), dma_rx->dma_desc_buff_tail_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_fetch_ctrl), dma_rx->dma_desc_fetch_ctrl);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_timer), dma_rx->dma_int_delay_timer);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_pktcnt), dma_rx->dma_int_delay_pktcnt);

	tsrn10_dbg("\n");
	dma_rx = &card_hardware.dma0_tx;
	tsrn10_dbg("dma0_tx status:\n");
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_high), dma_rx->dma_desc_buff_base_addr_high);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_low), dma_rx->dma_desc_buff_base_addr_low);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_len), dma_rx->dma_desc_buff_len);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_head_ptr), dma_rx->dma_desc_buff_head_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_tail_ptr), dma_rx->dma_desc_buff_tail_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_fetch_ctrl), dma_rx->dma_desc_fetch_ctrl);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_timer), dma_rx->dma_int_delay_timer);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_pktcnt), dma_rx->dma_int_delay_pktcnt);

	tsrn10_dbg("\n");
	dma_rx = &card_hardware.dma1_rx;
	tsrn10_dbg("dma1_rx status:\n");
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_high), dma_rx->dma_desc_buff_base_addr_high);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_low), dma_rx->dma_desc_buff_base_addr_low);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_len), dma_rx->dma_desc_buff_len);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_head_ptr), dma_rx->dma_desc_buff_head_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_tail_ptr), dma_rx->dma_desc_buff_tail_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_fetch_ctrl), dma_rx->dma_desc_fetch_ctrl);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_timer), dma_rx->dma_int_delay_timer);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_pktcnt), dma_rx->dma_int_delay_pktcnt);

	tsrn10_dbg("\n");
	dma_rx = &card_hardware.dma1_tx;
	tsrn10_dbg("dma1_tx status:\n");
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_high), dma_rx->dma_desc_buff_base_addr_high);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_base_addr_low), dma_rx->dma_desc_buff_base_addr_low);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_len), dma_rx->dma_desc_buff_len);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_head_ptr), dma_rx->dma_desc_buff_head_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_buff_tail_ptr), dma_rx->dma_desc_buff_tail_ptr);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_desc_fetch_ctrl), dma_rx->dma_desc_fetch_ctrl);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_timer), dma_rx->dma_int_delay_timer);
	tsrn10_dbg("%s:0x%08x\n", VNAME(dma_rx->dma_int_delay_pktcnt), dma_rx->dma_int_delay_pktcnt);
#else

#endif
}
