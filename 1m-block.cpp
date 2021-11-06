#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnet.h>

#define IPv4 4
#define IPv4_HDR_LENGTH 20
#define TCP 6

char* target;

void usage(void) {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.csv\n");
}


#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>

std::unordered_set <std::string> st;

int read_file(void) {
    // target이 파일 이름

	std::ifstream fout;
	fout.open(target);
	if(fout.fail()) {
		printf("file open failed");
		return -1;
	}

    // 한줄 씩
	std::string s;

	
	while(!fout.eof()) {
		std::getline(fout, s);
		// 구분은 CRLF로 됨.
		st.insert(s.substr(0, s.size()-1));
	}
	// 대충 1초 걸림
	std::cout << st.size() << std::endl;

	fout.close();
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

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

	ret = nfq_get_payload(tb, &data);
	// ip패킷 시작
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}

static u_int32_t get_id (struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) id = ntohl(ph->packet_id);
	return id;
}

// FreeBSD 코드 가져옴
char* strnstr(char* s, char* find, int slen) {
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == '\0' || slen-- < 1)
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	const char *data_;
	u_int32_t id = get_id(nfa);
	int ret = nfq_get_payload(nfa, (unsigned char**)&data_);

	struct libnet_ipv4_hdr* ip_hdr;
	struct libnet_tcp_hdr* tcp_hdr;

	// ip header 처리
	//memcpy(&ip_hdr, data_, sizeof(struct libnet_ipv4_hdr));
	ip_hdr = (struct libnet_ipv4_hdr*)data_;
	// version 확인
	if(ip_hdr->ip_v != IPv4) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	// protocol 확인
	if(ip_hdr->ip_p != TCP) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	// ip_header_length 계산
	int ip_length = ip_hdr->ip_hl << 2;

	// tcp header 처리
	//memcpy(&tcp_hdr, &data_[ip_length], sizeof(struct libnet_tcp_hdr));
	tcp_hdr = (struct libnet_tcp_hdr*)&data_[ip_length];
	// 포트 확인
	//if(ntohs(tcp_hdr->th_dport) != 80 && ntohs(tcp_hdr->th_sport) != 80) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	// tcp_header_length 계산
	int tcp_header_length = tcp_hdr->th_off << 2;

	// 페이로드 시작 위치 계산
	int tcp_segment_offset = ip_length + tcp_header_length;
	int tcp_segment_length = ret - tcp_segment_offset;
	// 페이로드가 있는지 확인
	if(tcp_segment_offset == ret) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	// c -> c++
	// HTTP 메서드인지 확인
	// 전역변수로 선언해보자
	const char* HTTP_METHOD[9] = {"PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "HEAD", "POST","GET"}; 
	const char* HTTP = "HTTP";
	int HTTP_METHOD_LENGTH[9] = {3, 6, 7, 7, 5, 5, 4, 4, 3 };
	const char* CRLF = "\r\n";
	const char* HOST = "Host:";
	int HOST_LENGTH = strlen(HOST);
	//HTTP 를 찾는 것이 효율적일지 메서드를 찾는 것이 효율적일지

	int res = 1;
	for(int i = 9; i--; ) {
		// tcp_segment_offset 범위를 벗어나는지 체크
		if(tcp_segment_offset + HTTP_METHOD_LENGTH[i] > ret) continue;

		res = strncmp(&data_[tcp_segment_offset], HTTP_METHOD[i], HTTP_METHOD_LENGTH[i]);
		// Host 찾기
		if(res == 0) {	
			char* host_ptr = strnstr((char*)&data_[tcp_segment_offset], (char*)HOST, ret - tcp_segment_offset);
			
			if(host_ptr != NULL) {
				// "Host:" 인지 "Host: " 인지
				if(*(host_ptr + HOST_LENGTH) == ' ') host_ptr += HOST_LENGTH + 1;
				else host_ptr += HOST_LENGTH;
					
				// url 시작 주소까지 offset
				int site_offset = host_ptr - data_;
				char* crlf_ptr = strnstr(host_ptr, (char*)CRLF, ret - site_offset);

				// crlf_ptr이 NULL이 아니면 
				if(crlf_ptr != NULL) {
					std::string site;	
					int site_length = crlf_ptr - host_ptr;

					for(int j = 0; j < site_length; j++) {
						site.push_back(*(host_ptr + j));
					}
					std::cout << site << std::endl;
					auto ptr = st.find(site);
					//std::cout << "find result: " << *ptr << std::endl;
					if(ptr != st.end()) {
						// DROP
						return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					}	
				}
			}
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	// 
	if(argc != 2) {
		usage();
		return 0;
	}
	target = argv[1];
	read_file();
	//

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
			// printf("pkt received\n");
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
