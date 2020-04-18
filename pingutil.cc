#include <string>
#include <cassert>
#include <iostream>
#include <cstdio>
#include <vector>
#include <iomanip>

#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>

#include "include/cxxopts.hpp"


namespace pingutil {
	
	class Pinger {
	private:
		
		int sockfd; /* file descriptor for the socket */

		static const int ICMP_PACKET_SIZE = 64;

		/* ICMP packets have 8 byte header followed by variable size data section
		See https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol or https://tools.ietf.org/html/rfc792 */
		struct icmp_packet {
			struct icmphdr hdr;
			char data[ICMP_PACKET_SIZE - sizeof(struct icmphdr)];
		};

		struct overall_stats {
			int packets_transmitted; 	/* number of ECHO_REQUEST send */
			int packets_received; 		/* number of ECHO_REPLY recevied */
			std::vector<double> rtt;	/* round trip delay time for each ECHO request */
		} stats;

		/* set by signal handler to exit ping loop */
		bool exit_ping_loop = false;
		
		/* Checksum() : calculates checksum for ICMP Header */
		unsigned short Checksum(void *b, int len) 
		{ 	unsigned short *buf = (unsigned short *)b; 
			unsigned int sum=0; 
			unsigned short result; 

			for ( sum = 0; len > 1; len -= 2 ) 
				sum += *buf++; 
			
			if ( len == 1 ) 
				sum += *(unsigned char*)buf; 
			
			sum = (sum >> 16) + (sum & 0xFFFF); 
			sum += (sum >> 16); 
			result = ~sum; 
			return result; 
		} 
		
		/* ResolveHostName() : Performs a DNS lookup for the given hostname */
		sockaddr* ResolveHostName(std::string hostname, int addr_family) {
			
			/* requested address must be either IPv4 or IPv6 */
			if (addr_family != AF_INET && addr_family != AF_INET6)
				return NULL;
				
			struct sockaddr *saddr = NULL;
			struct addrinfo *result;
			int error;
			
			/* resolve the hostname into a list of address */
			if (error = getaddrinfo(hostname.c_str(), NULL, NULL, &result) != 0) {
				return NULL;
			}
			
			/* use the first address from list of addresses returned by getaddrinfo() */
			for (struct addrinfo *r = result; r != NULL; r = r->ai_next) {
				if (r->ai_family == addr_family) {
					if (r->ai_family == AF_INET) {
						saddr = (sockaddr*) malloc(sizeof(sockaddr_in));
						memcpy(saddr, r->ai_addr, sizeof(sockaddr_in));
					}
					else if (r->ai_family == AF_INET6){
						saddr = (sockaddr*) malloc(sizeof(sockaddr_in6));
						memcpy(saddr, r->ai_addr, sizeof(sockaddr_in6));
					}
					break;
				} 
			} 
			
			freeaddrinfo(result);
			return saddr;
		}

		/* GetHostName() : Performs a reverse DNS lookup for the given address */
		char* GetHostName(struct sockaddr* address, int addrlen) {
			char *hostname = (char*)malloc(256);
			if ( getnameinfo(address, addrlen, hostname, 256, NULL, 0, NI_NAMEREQD) != 0) {
				free(hostname);
				return NULL;
			}
			return hostname;
		}
		
		/* PingV4() : Sends a ICMP ECHO request to the given IPv4 address. */
		int PingV4(struct sockaddr_in *target, int ttl, int count, int timeout) {
			if (target == NULL)
				return -1;
				
			/* create a raw socket. Creating a raw socket requires root privilges. */ 
			int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			if ( sockfd  < 0 ) {
				std::cout<<"Unable to create socket. Raw sockets require super user privileges.\n";
				return -1;
			}
			
			/* set Time to Live (TTL) value */ 
			if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) 
			{ 
				std::cout<<"Unable to set Time To Live (TTL). \n"; 
				return -1; 
			} 

			/* set RECEIVE_TIMOUT on the socket as we don't want to wait forever for a response. */
			struct timeval recvtimout;
			recvtimout.tv_sec = timeout;
			recvtimout.tv_usec = 0;
			if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recvtimout, sizeof(recvtimout)) != 0) {
				std::cout<<"Unable to set Receive Timout. \n"; 
				return -1;
			}

			char *domain_name = GetHostName((struct sockaddr *)target, sizeof(*target));
			char ip[256]; 			
			inet_ntop(AF_INET, &(target->sin_addr), ip, 255);
			
			struct icmp_packet ipkt;
			unsigned int ping_cnt = 0;
			char buf[512]; /* buffer to store incoming packets */

			if (domain_name != NULL)
				std::cout<<"PING "<<domain_name<<" ("<<ip<<") with 56 bytes of data (icmp packet size = 64 bytes)\n";
			else
				std::cout<<"PING "<<ip<<" with 56 bytes of data (icmp packet size = 64 bytes)\n";

			while (!exit_ping_loop and ping_cnt < count) {

				bzero(&ipkt, sizeof(ipkt));				
				ipkt.hdr.type = ICMP_ECHO;
				ipkt.hdr.code = 0;
				ipkt.hdr.un.echo.id = htons(getpid());
				ipkt.hdr.un.echo.sequence = htons(++ping_cnt);
				ipkt.hdr.checksum = Checksum(&ipkt, sizeof(ipkt));

				/* remember the current time to calculate round trip delay */
				struct timespec time_start, time_end;
				clock_gettime(CLOCK_MONOTONIC, &time_start); 

				/* flag is whether packet was sent or not */ 
				bool packet_sent = true; 

				if (sendto(sockfd, &ipkt, sizeof(ipkt), 0, (struct sockaddr*) target, sizeof(*target)) <= 0) { 
					std::cout<<"Unable to send packet. Retrying again. \n";
					packet_sent = false; 
				} 

				stats.packets_transmitted++;

				struct sockaddr_in recv_addr;
				socklen_t addr_len = sizeof(recv_addr);

				int tries = 3;
				bool packet_received = false;
				while (tries-- && !exit_ping_loop) {
					if (packet_sent && recvfrom(sockfd, buf, 500, 0, (struct sockaddr*) &recv_addr, &addr_len) <= 0) { 
						continue;
					}
					else if (packet_sent) {

						/* strip IPv4 header */
						struct iphdr *iphdr = (struct iphdr *)buf;
						struct icmp_packet *recv_icmp_pkt = (struct icmp_packet *)(buf + (iphdr->ihl << 2));
						recv_icmp_pkt->hdr.type = ntohs(recv_icmp_pkt->hdr.type);
						recv_icmp_pkt->hdr.un.echo.sequence = ntohs(recv_icmp_pkt->hdr.un.echo.sequence);

						if (recv_icmp_pkt->hdr.type == ICMP_ECHOREPLY) {
							
							if (recv_icmp_pkt->hdr.un.echo.sequence < ping_cnt)
								continue;

							stats.packets_received++;

							clock_gettime(CLOCK_MONOTONIC, &time_end); 
							PrintStats(time_start, time_end, domain_name, ip, iphdr->ttl, recv_icmp_pkt->hdr.un.echo.sequence);
							packet_received = true;
							break;
						}

						if (recv_icmp_pkt->hdr.type == ICMP_DEST_UNREACH) {
							std::cout<<"Destination Host Unreachable\n";
							packet_received = true;
							break;
						}

						if (recv_icmp_pkt->hdr.type == ICMP_TIME_EXCEEDED) {
							std::cout<<"Time Exceeded\n";
							packet_received = true;
							break;
						}
					}
				}

				if (!packet_received) {
					std::cout<<"Received No Response. \n";
				}

				/* sleep for 1 second */
				usleep(1000000);
			}

			PrintOverallStats(domain_name, ip);

			/* free memory */
			free(domain_name);
			close(sockfd);
			return 0;
		}

		/* PingV6() : Sends a ICMPv6 ECHO request to the given IPv6 address. */
		int PingV6(struct sockaddr_in6 *target, int ttl, int count, int timeout) {
			if (target == NULL)
				return -1;
				
			/* create a raw socket. Creating a raw socket requires root privilges. */ 
			int sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			if ( sockfd  < 0 ) {
				std::cout<<"Unable to create socket. Raw sockets require super user privileges.\n";
				return -1;
			}
\
			/* set Time to Live (TTL) value */ 
			if (setsockopt(sockfd, SOL_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) != 0) 
			{ 
				std::cout<<"Unable to set Time To Live (TTL). \n"; 
				return -1; 
			} 

			/* set RECEIVE_TIMOUT on the socket as we don't want to wait forever for a response. */
			struct timeval recvtimout;
			recvtimout.tv_sec = timeout;
			recvtimout.tv_usec = 0;
			if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recvtimout, sizeof(recvtimout)) != 0) {
				std::cout<<"Unable to set Receive Timout. \n"; 
				return -1;
			}
			
			char *domain_name = GetHostName((struct sockaddr *)target, sizeof(*target));
			char ip[256]; 			
			inet_ntop(AF_INET6, &(target->sin6_addr), ip, 255);

			struct icmp_packet ipkt;
			unsigned int ping_cnt = 0;

			if (domain_name != NULL)
				std::cout<<"PING "<<domain_name<<" ("<<ip<<") with 56 bytes of data (icmp packet size = 64 bytes)\n";
			else
				std::cout<<"PING "<<ip<<" with 56 bytes of data (icmp packet size = 64 bytes)\n";

			while (!exit_ping_loop and ping_cnt < count) {

				bzero(&ipkt, sizeof(ipkt));				
				ipkt.hdr.type = ICMP6_ECHO_REQUEST;
				ipkt.hdr.code = 0;
				ipkt.hdr.un.echo.id = getpid();
				ipkt.hdr.un.echo.sequence = ++ping_cnt;

				/* calculate checksum for the packet */
				ipkt.hdr.checksum = Checksum(&ipkt, sizeof(ipkt));

				/* remember the current time to calculate round trip delay */
				struct timespec time_start, time_end;
				clock_gettime(CLOCK_MONOTONIC, &time_start); 

				/* flag is whether packet was sent or not */ 
				bool packet_sent = true; 

				if (sendto(sockfd, &ipkt, sizeof(ipkt), 0, (struct sockaddr*) target, sizeof(*target)) <= 0) { 
					std::cout<<"Unable to send packet. Retrying again. \n";
					packet_sent = false; 
				} 

				stats.packets_transmitted++;
					
				char buf[500]; /* to store the incoming packets */
				struct sockaddr_in recv_addr;
				socklen_t addr_len = sizeof(recv_addr);
				
				int tries = 3;
				bool packet_received = false;
				while (tries-- && !exit_ping_loop) {
					if (packet_sent && recvfrom(sockfd, buf, 500, 0, (struct sockaddr*) &recv_addr, &addr_len) <= 0) { 
						continue;
					}
					else if (packet_sent) {
						struct icmp_packet *recv_icmp_pkt = (struct icmp_packet *)buf;

						if (recv_icmp_pkt->hdr.type == ICMP6_ECHO_REPLY) {
							
							if (recv_icmp_pkt->hdr.un.echo.sequence < ping_cnt)
								continue;

							stats.packets_received++;

							clock_gettime(CLOCK_MONOTONIC, &time_end); 
							PrintStats(time_start, time_end, domain_name, ip, ttl, recv_icmp_pkt->hdr.un.echo.sequence);
							packet_received = true;
							break;
						}

						if (recv_icmp_pkt->hdr.type == ICMP6_DST_UNREACH) {
							std::cout<<"Destination Host Unreachable\n";
							packet_received = true;
							break;
						}

						if (recv_icmp_pkt->hdr.type == ICMP6_TIME_EXCEEDED) {
							std::cout<<"Time Exceeded\n";
							packet_received = true;
							break;
						}

					}
				}
				
				if (!packet_received) {
					std::cout<<"Received No Response. \n";
				}
				/* sleep for 1 second */
				usleep(1000000);
			}

			PrintOverallStats(domain_name, ip);

			/* free memory */
			free(domain_name);
			close(sockfd);
			return 0;
		}

		/* PrintStats() : prints statistics for a single ping. */
		void PrintStats(struct timespec time_start, struct timespec time_end, char *domain_name, char *ip, int ttl, int imcp_seq) {
			double rtt; /* round trip delay in milliseconds */
			rtt = double(time_end.tv_sec - time_start.tv_sec) * 1000.0 + double(time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;
			stats.rtt.push_back(rtt); /* keep rtt to gather overall statistics */

			std::cout<<ICMP_PACKET_SIZE<<" bytes from "<<domain_name<<" ("<<ip<<"): icmp_seq="
					 <<imcp_seq<<" ttl="<<ttl<<" time="<<rtt<<"ms\n";
		}

		/* PrintOverallStats() : prints statistics for a single ping. */
		void PrintOverallStats(char *domain_name, char *ip) {
			if (domain_name)
				std::cout<<"--- "<<domain_name<<" ping statistics ---\n";
			else
				std::cout<<"--- "<<ip<<" ping statistics ---\n";

			double total_rtt;
			double min_rtt = 1e8;
			double max_rtt = 0;
			double avg_rtt;
			double mdev_rtt;
			for (double rtt : stats.rtt) {
				total_rtt += rtt;
				min_rtt = std::min(min_rtt, rtt);
				max_rtt = std::max(max_rtt, rtt);				
			}

			avg_rtt = total_rtt / stats.rtt.size();
			for (double rtt : stats.rtt)
				mdev_rtt = abs(rtt - avg_rtt);
			mdev_rtt /= stats.rtt.size();

			double loss = 1  - (stats.packets_received/stats.packets_transmitted);
			loss = loss * 100;
			
			std::cout<<stats.packets_transmitted<<" packets transmitted, "<<stats.packets_received<<" received, "
				 	 <<std::fixed<<std::setprecision(2)<<loss<<"% packet loss, time "<<total_rtt<<"ms\n"
				 	 <<"rtt min/avg/max/mdev = "<<min_rtt<<"/"<<avg_rtt<<"/"<<max_rtt<<"/"<<mdev_rtt<<" ms\n";
		}

	
	public:

		void StopPingLoop() {
			exit_ping_loop = true;
		}
		
		/* Ping() : Pings the host specified by the given IPv4/IPv6 address or domain name. */
		int Ping(std::string host, int ttl, int count, int timeout, bool forceip4=false, bool forceip6=false) {
			
			/* if IPv4 address is provided */
			if (std::count(host.begin(), host.end(), '.') == 3) {
				bool valid_ip4 = true;
				for (char c : host)
					if (c != '.' && !isdigit(c)) {
						valid_ip4 = false;
						break;
					}

				if (forceip6) {
					std::cout<<"Address family for hostname not supported.\n";
					return -1;
				}

				if (valid_ip4) {
					struct sockaddr_in addr;
					addr.sin_family = AF_INET;
					addr.sin_port = 0;
					inet_pton(AF_INET, host.c_str(), &(addr.sin_addr));
					return PingV4(&addr, ttl, count, timeout);
				}
			} 

			/* if IPv6 address is provided */
			if (std::count(host.begin(), host.end(), '.') == 0 && std::count(host.begin(), host.end(), ':')) {
				if (forceip4) {
					std::cout<<"Address family for hostname not supported.\n";
					return -1;
				}
				
				struct sockaddr_in6 addr;
				addr.sin6_family = AF_INET6;
				addr.sin6_port = 0;
				inet_pton(AF_INET6, host.c_str(), &(addr.sin6_addr));
				return PingV6(&addr, ttl, count, timeout);
			}

			/* Since we exhausted all possibilities, assuming hostname is provided */
			if (forceip4 || !forceip6) {
				struct sockaddr_in *addr = (sockaddr_in*) ResolveHostName(host.c_str(), AF_INET);
				if (!addr) {
					std::cout<<"Unable to resolve hostname.\n";
					return -1;
				}
				int err = PingV4(addr, ttl, count, timeout);
				free(addr);
				return err; 				
			}

			/* Must be forced IPv6 */
			struct sockaddr_in6 *addr = (sockaddr_in6*) ResolveHostName(host.c_str(), AF_INET6);
			if (!addr) {
				std::cout<<"Unable to resolve hostname.\n";
				return -1;
			}
			int err = PingV6(addr, ttl, count, timeout);
			free(addr);
			return err;
		}	
	};

}

pingutil::Pinger pngr;

void SigIntHandler(int sig) {
	pngr.StopPingLoop();
}


int main(int argc, char *argv[]) {

	std::string help_str = "pingutil - Send ICMPv4/ICMPv6 ECHO_REQUEST to network hosts.\n"
	"\nExample Usage : >> pingutil facebook.com"
	"\n >> pingutil 157.240.16.35"
	"\n >> pingutil --ttl 100 google.com"
	"\n >> pingutil 2a03:2880:f12f:83:face:b00c:0:25de"
	"\n >> pingutil -6 google.com"
	"\n >> pingutil -c 10 -4 google.com \n";

	cxxopts::Options options("pingutil", help_str);

	options.positional_help("<destination_host>");

	options.add_options()
        ("c,count", "stop after given responses", cxxopts::value<int>())
        ("d,timeout", "time to wait for response in seconds", cxxopts::value<int>()->default_value("1"))
        ("t,ttl", "set time to live", cxxopts::value<int>()->default_value("64"))
        ("4,forceip4", "use IPv4")
		("6,forceip6", "use IPv6")
		("h,help", "print help")
		("destination_host", "Hostname or IPv4/IPv6 address of the destination network host", cxxopts::value<std::string>())
    ;

	options.parse_positional({"destination_host"});
	
	auto args = options.parse(argc, argv);

	/* print help */
	if (args.count("help")) {
		std::cout<<options.help()<<'\n';
		return 0;
	}

	/* extract options from arguments */
	int count = 1000; /* no limit */
	int timeout = 3; /* 3 seconds */
	int ttl = 64; /* deafult time to live */
	bool forceip4 = false;
	bool forceip6 = false;
	std::string destination_host;

	if (args.count("count")) {
		count = args["count"].as<int>();
	}

	if (args.count("timeout")) {
		timeout = args["timeout"].as<int>();
	}

	if (args.count("ttl")) {
		ttl = args["ttl"].as<int>();
	}

	if (args.count("forceip4")) {
		forceip4 = true;
	}

	if (args.count("forceip6")) {
		forceip6 = true;
	}

	if (!args.count("destination_host")) {
		std::cout<<"Please specify a network host to send ICMP ECHO requests. Use --help option to learn more.\n";
		return 0;
	}

	destination_host = args["destination_host"].as<std::string>();
	signal(SIGINT, SigIntHandler);
	pngr.Ping(destination_host, ttl, count, timeout, forceip4, forceip6);
	return 0;
}
