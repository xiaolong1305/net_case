#include <stdio.h>
//#include <uinst.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "net_lib.h"
#include <pthread.h>
#include <unistd.h>

int test_port(iface_priv_t * iface, int sendcount)
{
	struct msg_buff_s msg;
	int i;
	msg.length = MAX_DMA_LEN;
	int ret;
	ret = net_open(iface);
	for (i = 0; i < sendcount; i++) {
		memset(msg.data, i, MAX_DMA_LEN);
		ret = net_tx(iface, &msg);
		//simulate_hardware_tx_to_rx(iface);
		// a hardware pthread?  
		usleep(20);
		//net_intr(iface->card);
	}
	//simulate handle packet
	while (iface->rece_count < sendcount) {
		usleep(5);
	}
	
	net_release(iface);
//	net_intr(iface->card);
}

int init_iface(iface_priv_t *iface, card_t *card,int eth)
{
	iface->card = card;
	iface->iface = eth;
	iface->rece_count = 0;
	iface->rece_count = 0;
	return 0;
}
int main()
{
	card_t card;
	//init two port
	iface_priv_t iface_a, iface_b;
	int ret;
	ret = init_iface(&iface_a, &card, 0);
	ret = init_iface(&iface_b, &card, 1);

	simulate_hardware_init();
	ret = init_card(&card);
	card.iface[0] = &iface_a;
	card.iface[1] = &iface_b;
	//start interupt simulate
/*	pthread_t interupt_pthread;
	if (pthread_create(&interupt_pthread, NULL, simulate_intr, &card)!=0) {
		tsrn10_dbg("create interupt error\n");
	}
	else {
		tsrn10_dbg("create interupt ok\n");
	}

	pthread_t hardware_pthread;
	if (pthread_create(&hardware_pthread, NULL, simulate_hardware_pthread, &iface_a) != 0) {
		tsrn10_dbg("create phtread iface a error\n");
	}
	else {
		tsrn10_dbg("create pthread iface a ok\n");
	}*/

	test_port(&iface_a,10);
	
	stop_hardware_pthread();
	deinit_card(&card);
    printf("hello from net_case!\n");
    return 0;
}