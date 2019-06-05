#include "comnet.h"

int getData(int sd)
{
	struct ifreq nic;
	int index, i;
	char select, interface_name[10];

	printf(" Elije la interfaz de red a utilizar\n 1.-enp2s0\n 2.-wlp3s0\n 3.-Salir\n -> ");
	scanf("%c", &select);

	switch (select)
	{
	case '1':
		strcpy(interface_name, "enp2s0");
		break;

	case '2':
		strcpy(interface_name, "wlp3s0");
		break;

	default:
		printf("Error al seleccionar la interfaz de red.\n");
		exit(1);
		break;
	}

	strcpy(nic.ifr_name, interface_name);

	/* obtener el indice de la interfaz de red */

	if (ioctl(sd, SIOCGIFINDEX, &nic) == -1)
	{
		perror("Error al obtener el indice\n");
		exit(1);
	}
	else
	{
		index = nic.ifr_ifindex;
	}

	/* obtener mi direccion MAC */

	if (ioctl(sd, SIOCGIFHWADDR, &nic) == -1)
	{
		perror("Error al obtener la MAC\n");
		exit(1);
	}
	else
	{
		memcpy(my_MAC, nic.ifr_hwaddr.sa_data + 0, 6);
		printf(" Mi direccion MAC es: ");

		for (i = 0; i < 6; i++)
		{
			if (i == 5)
				printf("%.2X\n", my_MAC[i]);
			else
				printf("%.2X:", my_MAC[i]);
		}
	}

	/* obtener mi direccion IP */

	if (ioctl(sd, SIOCGIFADDR, &nic) == -1)
	{
		perror("Error al obtener la dirección IP\n");
		exit(1);
	}
	else
	{
		memcpy(my_IP, nic.ifr_addr.sa_data + 2, 4);
		printf(" Mi direccion IP es: ");

		for (i = 0; i < 4; i++)
		{
			if (i == 3)
				printf("%d\n", my_IP[i]);
			else
				printf("%d.", my_IP[i]);
		}
	}

	/* obtener mi mascara de subred */

	if (ioctl(sd, SIOCGIFNETMASK, &nic) == -1)
	{
		perror("Error al obtener la mascara de subred\n");
		exit(1);
	}
	else
	{
		memcpy(NETMASK, nic.ifr_netmask.sa_data + 2, 4);
		printf(" Mi mascara de subred es: ");

		for (i = 0; i < 4; i++)
		{
			if (i == 3)
				printf("%d\n", NETMASK[i]);
			else
				printf("%d.", NETMASK[i]);
		}
	}

	/* obtener la metrica */

	if (ioctl(sd, SIOCGIFMETRIC, &nic) == -1)
	{
		perror("Error al obtener la metrica\n");
		exit(1);
	}
	else
	{
		Metric = nic.ifr_metric;
		printf(" Mi metrica es: %d\n", Metric);
	}

	/* obtener el MTU */

	if (ioctl(sd, SIOCGIFMTU, &nic) == -1)
	{
		perror("Error al obtener el MTU\n");
		exit(1);
	}
	else
	{
		MTU = nic.ifr_mtu;
		printf(" Mi MTU es: %d\n", MTU);
	}

	printf("\n");

	return index;
}

void ARPframe(unsigned char *frame, unsigned char *s_MAC, unsigned char *s_IP, unsigned char *d_MAC, unsigned char *d_IP)
{
	memcpy(frame + 0, bro_MAC, 6);
	memcpy(frame + 6, s_MAC, 6);
	memcpy(frame + 12, ethertype_ARP, 2);
	memcpy(frame + 14, HW, 2);
	memcpy(frame + 16, PR, 2);
	memcpy(frame + 18, LDH, 1);
	memcpy(frame + 19, LDP, 1);
	memcpy(frame + 20, epcode_ARP_request, 2);
	memcpy(frame + 22, s_MAC, 6);
	memcpy(frame + 28, s_IP, 4);
	memcpy(frame + 32, d_MAC, 6);
	memcpy(frame + 38, d_IP, 4);
}

void frame(unsigned char *frame)
{
	memcpy(frame + 0, alameda_MAC_WLAN, 6);
	memcpy(frame + 6, my_MAC, 6);
	memcpy(frame + 12, ethertype_ip, 2);
	memcpy(frame + 14, "Quintanilla Network", 40);
}

void sendFrame(int sd, int index, unsigned char *frame, int frame_size)
{
	int size;
	struct sockaddr_ll interface;

	memset(&interface, 0x00, sizeof(interface));
	interface.sll_family = AF_PACKET;
	interface.sll_protocol = htons(ETH_P_ALL);
	interface.sll_ifindex = index;

	size = sendto(sd, frame, frame_size, 0, (struct sockaddr *)&interface, sizeof(interface));

	if (size == -1)
	{
		perror("Error al enviar");
		exit(1);
	}
	else
	{
		//printf("Exito al enviar\n");
	}
}

void printFrame(unsigned char *frame, int size)
{
	int i = 0;
	printf(" %.2X\t", 16 * i);

	for (int j = 0; j < size - 1; j++)
	{
		if (j % 16 == 0 && j != 0)
		{
			printf("\n");
			i++;
			printf(" %.2X\t", 16 * i);
		}
		if (j % 8 == 0)
			printf(" ");
		printf("%.2X ", frame[j]);
	}
	printf("\n");
}

void printARPinfo(unsigned char *frame, int size)
{
	int i;

	if (!memcmp(frame + 20, epcode_ARP_request, 2))
		printf("\nSolicitud ARP\n");
	else if (!memcmp(frame + 20, epcode_ARP_replay, 2))
		printf("\nRespuesta ARP\n");

	printf("+---------------------------------------+\n");

	printf("Direccion MAC Origen: ");

	for (i = 22; i < 28; i++)
	{
		if (i == 27)
			printf("%.2X\n", frame[i]);
		else
			printf("%.2X:", frame[i]);
	}

	printf("Direccion IP Origen: ");

	for (i = 28; i < 32; i++)
	{
		if (i == 31)
			printf("%d\n", frame[i]);
		else
			printf("%d.", frame[i]);
	}

	printf("Direccion MAC Destino: ");

	for (i = 32; i < 38; i++)
	{
		if (i == 37)
			printf("%.2X\n", frame[i]);
		else
			printf("%.2X:", frame[i]);
	}

	printf("Direccion IP Destino: ");

	for (i = 38; i < 42; i++)
	{
		if (i == 41)
			printf("%d\n", frame[i]);
		else
			printf("%d.", frame[i]);
	}

	printf("+---------------------------------------+\n");
}

void receiveFrame(int sd, unsigned char *frame)
{
	int size, flag = 0;

	gettimeofday(&start, NULL);
	mtime = 0;

	while (mtime < 200)
	{

		size = recvfrom(sd, frame, 1514, MSG_DONTWAIT, NULL, 0);

		if (size == -1)
		{
			//perror("Error al recibir");
		}
		else
		{
			if (!memcmp(frame + 0, my_MAC, 6) && !memcmp(frame + 12, ethertype_ARP, 2) && !memcmp(frame + 20, epcode_ARP_replay, 2) && !memcmp(frame + 28, dest_IP, 4))
			{
				//printFrame(frame, size);
				flag = 1;
			}
		}

		gettimeofday(&end, NULL);

		seconds = end.tv_sec - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds)*1000 + useconds / 1000.0) + 0.5;

		if (flag == 1)
		{
			//printf("\nElapsed time: %ld milliseconds\n", mtime);
			break;
		}
	}

	if (flag == 0)
	{
		//perror("Error al recibir");
		//printf("Elapsed time: %ld milliseconds\n", mtime);
	}
}

void stringToIP(char *ip_s)
{
	inet_aton(ip_s, (struct in_addr *)IP);
}

char *IPToString(unsigned char *ip)
{
	char *ip_s = malloc(14);
	char aux[14];

	strcpy(ip_s, "");

	for (int i = 0; i < 4; i++)
	{
		if (i == 3)
			sprintf(aux, "%d", ip[i]);
		else
			sprintf(aux, "%d.", ip[i]);

		strcat(ip_s, aux);
	}

	return ip_s;
}

void gratARPreply(unsigned char *frame, unsigned char *s_MAC, unsigned char *d_MAC, unsigned char *d_IP)
{
	memcpy(frame + 0, s_MAC, 6);
	memcpy(frame + 6, d_MAC, 6);
	memcpy(frame + 12, ethertype_ARP, 2);
	memcpy(frame + 14, HW, 2);
	memcpy(frame + 16, PR, 2);
	memcpy(frame + 18, LDH, 1);
	memcpy(frame + 19, LDP, 1);
	memcpy(frame + 20, epcode_ARP_replay, 2);

	memcpy(frame + 22, d_MAC, 6);
	memcpy(frame + 28, d_IP, 4);
	memcpy(frame + 32, s_MAC, 6);
	memcpy(frame + 38, d_IP, 4);
}

void gratARPrequest(unsigned char *frame, unsigned char *d_MAC, unsigned char *d_IP)
{
	memcpy(frame + 0, bro_MAC, 6);
	memcpy(frame + 6, d_MAC, 6);
	memcpy(frame + 12, ethertype_ARP, 2);
	memcpy(frame + 14, HW, 2);
	memcpy(frame + 16, PR, 2);
	memcpy(frame + 18, LDH, 1);
	memcpy(frame + 19, LDP, 1);
	memcpy(frame + 20, epcode_ARP_request, 2);

	memcpy(frame + 22, d_MAC, 6);
	memcpy(frame + 28, d_IP, 4);
	memcpy(frame + 32, clear_MAC, 6);
	memcpy(frame + 38, d_IP, 4);
}

int isLocalIP(unsigned char *d_IP)
{
	for (int i = 0; i < 4; i++)
	{
		if (NETMASK[i] == 0)
			break;
		if (my_IP[i] != d_IP[i])
			return 0;
	}
	return 1;
}

int getGatewayIP(unsigned char *gateway_IP)
{
	int received_bytes = 0, msg_len = 0, route_attribute_len = 0;
	int sock = -1, msgseq = 0;
	struct nlmsghdr *nlh, *nlmsg;
	struct rtmsg *route_entry;
	struct rtattr *route_attribute;
	char gateway_address[INET_ADDRSTRLEN], interface[IF_NAMESIZE];
	char msgbuf[BUFFER_SIZE], buffer[BUFFER_SIZE];
	char *ptr = buffer;
	struct timeval tv;

	if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
	{
		perror("socket failed");
		return EXIT_FAILURE;
	}

	memset(msgbuf, 0, sizeof(msgbuf));
	memset(gateway_address, 0, sizeof(gateway_address));
	memset(interface, 0, sizeof(interface));
	memset(buffer, 0, sizeof(buffer));
	nlmsg = (struct nlmsghdr *)msgbuf;
	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_type = RTM_GETROUTE;				 // Get the routes from kernel routing table .
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlmsg->nlmsg_seq = msgseq++;					 // Sequence of the message packet.
	nlmsg->nlmsg_pid = getpid();					 // PID of process sending the request.
	tv.tv_sec = 1;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
	/* send msg */
	if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0)
	{
		perror("send failed");
		return EXIT_FAILURE;
	}

	do
	{
		received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);

		if (received_bytes < 0)
		{
			perror("Error in recv");
			return EXIT_FAILURE;
		}

		nlh = (struct nlmsghdr *)ptr;
		if ((NLMSG_OK(nlmsg, received_bytes) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR))
		{
			perror("Error in received packet");
			return EXIT_FAILURE;
		}

		if (nlh->nlmsg_type == NLMSG_DONE)
			break;
		else
		{
			ptr += received_bytes;
			msg_len += received_bytes;
		}

		if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
			break;
	} while ((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

	for (; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes))
	{
		route_entry = (struct rtmsg *)NLMSG_DATA(nlh);
		if (route_entry->rtm_table != RT_TABLE_MAIN)
			continue;

		route_attribute = (struct rtattr *)RTM_RTA(route_entry);
		route_attribute_len = RTM_PAYLOAD(nlh);

		for (; RTA_OK(route_attribute, route_attribute_len);
			 route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
		{
			switch (route_attribute->rta_type)
			{
			case RTA_OIF:
				if_indextoname(*(int *)RTA_DATA(route_attribute), interface);
				break;
			case RTA_GATEWAY:
				inet_ntop(AF_INET, RTA_DATA(route_attribute), gateway_address, sizeof(gateway_address));
				break;
			default:
				break;
			}
		}

		if ((*gateway_address) && (*interface))
		{
			stringToIP(gateway_address);
			memcpy(gateway_IP, IP, 4);
			break;
		}
	}

	close(sock);
	return 0;
}

void receiveARPFrame(int sd, unsigned char *frame)
{
	int size, flag = 0;

	gettimeofday(&start, NULL);
	mtime = 0;

	while (mtime < 200)
	{

		size = recvfrom(sd, frame, 1514, MSG_DONTWAIT, NULL, 0);

		if (size == -1)
		{
			//perror("Error al recibir");
		}
		else
		{
			if (!memcmp(frame + 0, my_MAC, 6) && !memcmp(frame + 12, ethertype_ARP, 2) && !memcmp(frame + 20, epcode_ARP_replay, 2) && !memcmp(frame + 28, dest_IP, 4))
			{
				//printARPinfo(frame, size);
				memcpy(dest_MAC, frame+22, 6);
				flag = 1;
			}
		}

		gettimeofday(&end, NULL);

		seconds = end.tv_sec - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds)*1000 + useconds / 1000.0) + 0.5;

		if (flag == 1)
		{
			//printf("\nElapsed time: %ld milliseconds\n", mtime);
			break;
		}
	}

	if (flag == 0)
	{
		//perror("Error al recibir");
		//printf("Elapsed time: %ld milliseconds\n", mtime);
	}
}

void UDP_Scan(int sd, int index)
{
	for(int i = 0; i <= 100 ; i++)
	{
		UDPframe(frame_s, htons(i));
		//printFrame(frame_s, 111);
		sendFrame(sd, index, frame_s, 110);
		
	}
}
void UDPframe(unsigned char *frame, unsigned int port)
{
	unsigned short chcksum;

	//MAC Header (14 bytes)
	memcpy(frame + 0, dest_MAC, 6);
	memcpy(frame + 6, my_MAC, 6);
	memcpy(frame + 12, ethertype_ip, 2);

	//IP Header (20 bytes)
	//4 bits - Version
				//0100 para la version ipv4
	//4 bits - Long enc ip
				// de 5 a 15                se multiplica la version y este para saber la longitud en bytes desde version al relleno
	//1 - Tipo de servicio regularmente 0x00
	//2 - Long datagrama ip
	//2 - id 								el emisor lo define (puede ser el pid)
	//3 bits - banderas
						//0
						//1 dont fragment
						//0 more fragments
	//13 bits - desplazamiento de fragmento
						//0 0000 0000 0000
	//1 - tiempo de vidda
						//0x80(128)
	//1 - protocolo (UDP == 0x11) (TCP == 0x06) (ICMP == 0x01)
	//2 - checksum calcular con este campo en cero primero
	//4 - ip origen
	//4 - ip destino

	memcpy(frame + 14, "\x45", 1);
	memcpy(frame + 15, "\x00", 1);
	memcpy(frame + 16, "\x00\x60", 2); // longitud con todo y udp en bytes
	memcpy(frame + 18, "\x00\x00", 2);
	memcpy(frame + 20, "\x40\x00", 2);
	memcpy(frame + 22, "\x80", 1);
	memcpy(frame + 23, "\x11", 1);
	memcpy(frame + 24, "\x00\x00", 2);
	memcpy(frame + 26, my_IP, 4);
	memcpy(frame + 30, IP, 4);

	memcpy(H_IP + 0, frame + 14, 20);

	chcksum = checksum(H_IP, (int)sizeof(H_IP));
	chcksum = htons(chcksum);

	memcpy(frame + 24, (char *)&chcksum, 2);

	//UDP Header (8 bytes)
	//2 - Puerto origen		0x00 0x00
	//2 - Puerto Destino	0x00 0x00, .... ...., 0xff 0xff
	//2 - Longitud			1458 longitud del mensaje
	//2 - Checksum			Pseudo encabezado + enc udp + mensaje + relleno ( 12 + 8 + ... + 1 ) bytes
							//Pseudoencabezado ip origen + ip destino + 0x00 + 0x11(17) + longitud udp
	
	memcpy(frame + 34, "\x00\x00", 2);
	memcpy(frame + 36, (unsigned char *)&port, 2);
	memcpy(frame + 38, "\x00\x44", 2);
	memcpy(frame + 40, "\x00\x00", 2);
	
	//UDP Message
	memcpy(frame + 42, "Kevin Jesus Olvera Olvera - kevin.jesus.olvera@gmail.com - IPN/ESCOM", 68);

	//Pseudo UDP Header + UDP Header + Message
	memcpy(H_UDP + 0, my_IP, 4);
	memcpy(H_UDP + 4, IP, 4);
	memcpy(H_UDP + 8, "\x00", 1);
	memcpy(H_UDP + 9, "\x11", 1);
	memcpy(H_UDP + 10, "\x4c", 1);

	memcpy(H_UDP + 11, frame + 34, 76);

	memcpy(H_UDP + 89, "\x00", 1);

	chcksum = checksum(H_UDP, (int)sizeof(H_UDP));
	chcksum = htons(chcksum);

    memcpy(frame + 40, (char *)&chcksum, 2);
}

unsigned short checksum(unsigned char *buff, int bufflen)
{
    unsigned short cksum = 0;
    unsigned short carry = 0;
    int i, addition = 0, result = 0, temp = 0;
    
    for (i = 0; i < bufflen; i = i + 2)
    {
        temp = (buff[i] << 8) + buff[i + 1];
        addition = addition + temp;
        temp = 0;
    }

    carry = addition >> 16;
    result = (addition & 0x0000FFFF) + carry;
    carry = result >> 16;
    result = (result & 0x0000FFFF) + carry;
    cksum = 0xffff - result;
    return cksum;
}