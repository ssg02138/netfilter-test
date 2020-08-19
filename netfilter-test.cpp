#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
//#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>

int continue_pkt = 0;
const char *site;

void dump(u_char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

void analysis(u_char* buf, int size) {
	int flag = 1;
	struct ip *ip_header;
	int ip_len;

	struct tcphdr *tcp_header;
	int tcp_len;

	u_char *payload;
	int payload_len;

	ip_header = (struct ip *)(buf);
	ip_len = ip_header->ip_hl << 2;

	if (ip_header->ip_p==IPPROTO_TCP) {
		tcp_header = (struct tcphdr *)(buf + ip_len);
		tcp_len = tcp_header->th_off << 2;

		payload = (u_char *)(buf + ip_len + tcp_len);
		payload_len = ntohs(ip_header->ip_len) - (tcp_len +ip_len);

		int i = 0;
		int j = 0;
		int cnt = 0;
		int check = 0;
		for (i = 0; i < payload_len; i++){
			if ( payload[i] == 0x0d && payload[i+1] == 0x0a ) {
				i += 2;
				if (cnt == 1) {
					for (int x = j; x < i; x++) {
						if (payload[x]==site[x-j]){
							check++;
						}
						if(check == (i-x-1)) {
							flag = 0;
							break;
						}
					}
					if(flag == 0) {
						break;
					}
				}
				cnt++;
				j = i;
			}
		}
	}
	if (flag == 0) {
		continue_pkt = 0;
		printf("\nDROP PKT...\n");
	} else {
		continue_pkt = 1;
		printf("\nACCPET PKT...\n");
	}
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	u_char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	// get_payload : pkt start/end point return
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d ", ret);
		analysis(data, ret);
	}

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	// set_verdict : NF_ACCEPT, NF_DROP Setting
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (continue_pkt == 1) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	} else {
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	if ( argc != 2 ) {
		printf("Usage: netfilter-test <host>\n");
		printf("sample : netfilter-test test.gilgil.net\n");
		exit(1);
	}
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	char tmp_site[100] {0};
       	strcat(tmp_site, "Host: ");
       	strcat(tmp_site, argv[1]);
       	strcat(tmp_site, "\r\n");

	site = tmp_site;

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

