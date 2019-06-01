#include "comnet.h"

int getData(int sd)
{
	struct ifreq nic;
	int index, i;
	char select, interface_name[10];

	printf("Elije la interfaz de red a utilizar\n 1.-enp2s0\n 2.-wlp3s0\n 3.-Salir\n -> ");
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
	
	if(ioctl(sd, SIOCGIFINDEX, &nic) == -1)
	{
		perror("Error al obtener el indice\n");
		exit(1);
	}
	else
	{
		index = nic.ifr_ifindex;
	}

	/* obtener mi direccion MAC */

	if(ioctl(sd, SIOCGIFHWADDR, &nic ) == -1)
	{
		perror("Error al obtener la MAC\n");
		exit(1);
	}
    else
    {
		memcpy(my_MAC, nic.ifr_hwaddr.sa_data+0, 6);
		printf("Mi direccion MAC es: ");
		
		for( i = 0 ; i < 6 ; i++ )
		{
			if(i == 5)
				printf("%.2X\n", my_MAC[i]);
			else
				printf("%.2X:", my_MAC[i]);
		}
	}

	/* obtener mi direccion IP */

	if(ioctl(sd, SIOCGIFADDR, &nic) == -1)
	{
		perror("Error al obtener la dirección IP\n");
		exit(1);
	}
	else
	{
		memcpy(my_IP, nic.ifr_addr.sa_data+2, 4);
		printf("Mi direccion IP es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
			if( i == 3 )
				printf("%d\n", my_IP[i]);
			else 
				printf("%d.", my_IP[i]);
		}
	}

	/* obtener mi mascara de subred */

	if(ioctl(sd, SIOCGIFNETMASK, &nic) == -1)
	{
		perror("Error al obtener la mascara de subred\n");
		exit(1);
	}
	else
	{
		memcpy(NETMASK, nic.ifr_netmask.sa_data+2, 4);
		printf("Mi mascara de subred es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
			if( i == 3 )
				printf("%d\n", NETMASK[i]);
			else 
				printf("%d.", NETMASK[i]);
		}
	}

	/* obtener la metrica */

	if(ioctl(sd, SIOCGIFMETRIC, &nic) == -1)
	{
		perror("Error al obtener la metrica\n");
		exit(1);
	}
	else
	{
		Metric = nic.ifr_metric;
		printf("Mi metrica es: %d\n", Metric);
	}

	/* obtener el MTU */

	if(ioctl(sd, SIOCGIFMTU, &nic) == -1)
	{
		perror("Error al obtener el MTU\n");
		exit(1);
	}
	else
	{
		MTU = nic.ifr_mtu;
		printf("Mi MTU es: %d\n", MTU);
	}

	printf("\n");

	return index;
}

void ARPframe(unsigned char *trama, unsigned char *s_MAC, unsigned char *s_IP, unsigned char *d_MAC, unsigned char *d_IP)
{
	memcpy(trama+0, bro_MAC, 6);
	memcpy(trama+6, s_MAC, 6);
	memcpy(trama+12, ethertype_ARP, 2);
	memcpy(trama+14, HW, 2);
	memcpy(trama+16, PR, 2);
	memcpy(trama+18, LDH, 1);
	memcpy(trama+19, LDP, 1);
	memcpy(trama+20, epcode_ARP_request, 2);
	memcpy(trama+22, s_MAC, 6);
	memcpy(trama+28, s_IP, 4);
	memcpy(trama+32, d_MAC, 6);
	memcpy(trama+38, d_IP, 4);
}

void frame(unsigned char *trama)
{
	memcpy(trama+0, alameda_MAC_WLAN, 6);
	memcpy(trama+6, my_MAC, 6);
	memcpy(trama+12, ethertype_ethernet, 2);
	memcpy(trama+14, "Quintanilla Network", 40);
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
	
	if(size == -1)
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
	int i;

	for( i = 0 ; i < size ; i++ )
	{
		if( i%16 == 0 )
			printf("\n");
		printf("%.2x ", frame[i]);
	}

	printf("\n");
}

void printARPinfo(unsigned char *frame, int size)
{
	int i;
	
	if(!memcmp(frame+20, epcode_ARP_request, 2))
		printf("Solicitud ARP\n");
	else if(!memcmp(frame+20, epcode_ARP_replay, 2))
		printf("Respuesta ARP\n\n");
	
	printf("+---------------------------------------+\n");

	printf("Direccion MAC Origen: ");

	for( i = 22 ; i < 28 ; i++ )
	{
		if(i == 27)
			printf("%.2X\n", frame[i]);
		else
			printf("%.2X:", frame[i]);
	}

	printf("Direccion IP Origen: ");

	for( i = 28 ; i < 32 ; i++ )
	{
		if( i == 31 )
			printf("%d\n", frame[i]);
		else 
			printf("%d.", frame[i]);
	}

	printf("Direccion MAC Destino: ");

	for( i = 32 ; i < 38 ; i++ )
	{
		if(i == 37)
			printf("%.2X\n", frame[i]);
		else
			printf("%.2X:", frame[i]);
	}

	printf("Direccion IP Destino: ");

	for( i = 38 ; i < 42 ; i++ )
	{
		if( i == 41 )
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
    
    while(mtime < 200){
		
		size = recvfrom(sd, frame, 1514, MSG_DONTWAIT, NULL, 0);

		if( size == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
			if( !memcmp(frame+0, my_MAC, 6) && !memcmp(frame+12, ethertype_ARP, 2) && !memcmp(frame+20, epcode_ARP_replay, 2) && !memcmp(frame+28, dest_IP, 4) )
			{
				//printFrame(frame, size);
				printARPinfo(frame, size);
				BD_MySQL_Save_Data(frame);
				flag = 1;
			}
	
		}
	
		gettimeofday(&end, NULL);

		seconds  = end.tv_sec  - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
		
		if( flag == 1 )
		{
			//printf("\nElapsed time: %ld milliseconds\n", mtime);
			break;
		}

	}

	if( flag == 0 ){
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

	for( int i = 0 ; i < 4 ; i++ )
	{
		if( i == 3 )
			sprintf(aux, "%d", ip[i]);
		else
			sprintf(aux, "%d.", ip[i]);

		strcat(ip_s, aux);
	}

	return ip_s;
}

void getDestinationIP(int index)
{
    dest_IP[0] = my_IP[0];
	dest_IP[1] = my_IP[1];
	dest_IP[2] = my_IP[2];

	char ip[14] = "";
	char aux[14] = "";
	
	for( int i = 0 ; i < 3 ; i++ ){
		sprintf(aux, "%d.", dest_IP[i]);
		strcat(ip, aux);
	}

	sprintf(aux, "%d", index);
	strcat(ip, aux);

	inet_aton(ip, (struct in_addr *)dest_IP);
}


void BD_MySQL_Connect()
{
	char *server = "localhost";
	char *user = "root";
	char *password = "root";
	char *database = "ARP_Scan";

	connection = mysql_init(NULL);
	/* Connect to database */
	
	if (!mysql_real_connect(connection, server, user, password, database, 0, NULL, 0))
	{
		fprintf(stderr, "%s\n", mysql_error(connection));
		exit(1);
	}
	else
	{
		perror("Exito al conectar con la base de datos");
	}
}

void BD_MySQL_Close()
{
	mysql_free_result(result);
	mysql_close(connection);
}

void BD_MySQL_Save_Data(unsigned char *frame)
{
	char ip[15] = "";
	char aux_ip[15] = "";
	char mac[17] = "";
	char aux_mac[17] = "";

	int i;

	for(i = 6;i < 12;i++)
	{
		if(i != 11)
			sprintf(aux_mac, "%.2X:", frame[i]);		
		else
			sprintf(aux_mac, "%.2X", frame[i]);

		strcat(mac, aux_mac);
	}

	for(i = 28;i < 32;i++)
	{
		if(i != 31)
			sprintf(aux_ip, "%d.", frame[i]);
		else
			sprintf(aux_ip, "%d", frame[i]);

		strcat(ip, aux_ip);
	}

	sprintf(consult, "insert into PC values(NULL, '%s', '%s');", ip, mac);
	
	if (mysql_query(connection, consult))
	{
		fprintf(stderr, "%s\n", mysql_error(connection));
		exit(1);
	}
	//else
		//printf("\nSe agrego a %s - %s", mac, ip);

}

void BD_MySQL_Show_Data()
{
	sprintf(consult, "select * from PC;");

	if((mysql_query(connection, consult) == 0))
	{
		result = mysql_use_result(connection);

		printf("+-------+---------------+-------------------+\n");
		printf("| PC_ID |  IP_Address\t|    MAC_Address    |\n");
		printf("+-------+---------------+-------------------+\n");

		while(row = mysql_fetch_row(result))
			printf("| %s\t| %s\t| %s |\n", row[0], row[1], row[2]);
		
		printf("+-------+---------------+-------------------+\n\n");
	}

	if(!mysql_eof(result))
		printf("Error de lectura %s\n", mysql_error(connection));
}

void BD_MySQL_Reset_Data()
{
	sprintf(consult, "truncate PC;");
	mysql_query(connection, consult);
	if((mysql_query(connection, consult) == 0))
	{
		result = mysql_use_result(connection);
	}
}

void ARPserver(int sd, int index)
{
	int size, flag = 0;

	gettimeofday(&start, NULL);
	mtime = 0;
    
    while(mtime < 1000)
	{
		size = recvfrom(sd, frame_r, 1514, MSG_DONTWAIT, NULL, 0);

		if( size == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
			if( !memcmp(frame_r+0, bro_MAC, 6) && !memcmp(frame_r+12, ethertype_ARP, 2) && !memcmp(frame_r+20, epcode_ARP_request, 2) && (!memcmp(frame_r+28, frame_r+38, 4) || !memcmp(frame_r+28, clear_IP, 4)) )
			{

				memcpy(source_MAC, frame_r+22, 6);
				memcpy(source_IP, frame_r+38, 4);

				if( BD_MySQL_Find_IP(IPToString(source_IP)) == 1 )
				{
					if( memcmp(source_MAC, MAC, 6) )
					{
						printARPinfo(frame_r, size);
						
						gratARPreply(frame_s, source_MAC, MAC, source_IP);
						sendFrame(sd, index, frame_s, 42);

						gratARPrequest(frame_s, MAC, source_IP);
						sendFrame(sd, index, frame_s, 42);

						memcpy(source_MAC, frame_r+22, 6);

						for( int i = 0 ; i < 6 ; i++ )
						{
							if(i == 5)
								printf("%.2X ", source_MAC[i]);
							else
								printf("%.2X:", source_MAC[i]);
						}
						printf("ha intentado conectarse a ");
						for( int i = 0 ; i < 4 ; i++ ){
							if( i == 3 )
								printf("%d\n\n", source_IP[i]);
							else 
								printf("%d.", source_IP[i]);
						}
					}					
				}					
			
				flag = 1;
			}
		}
	
		gettimeofday(&end, NULL);

		seconds  = end.tv_sec  - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
		
		if( flag == 1 )
			break;
	}
}

void gratARPreply(unsigned char *frame, unsigned char *s_MAC, unsigned char *d_MAC, unsigned char *d_IP)
{
	memcpy(frame+0, s_MAC, 6);
	memcpy(frame+6, d_MAC, 6);
	memcpy(frame+12, ethertype_ARP, 2);
	memcpy(frame+14, HW, 2);
	memcpy(frame+16, PR, 2);
	memcpy(frame+18, LDH, 1);
	memcpy(frame+19, LDP, 1);
	memcpy(frame+20, epcode_ARP_replay, 2);

	memcpy(frame+22, d_MAC, 6);
	memcpy(frame+28, d_IP, 4);
	memcpy(frame+32, s_MAC, 6);
	memcpy(frame+38, d_IP, 4);
}

void gratARPrequest(unsigned char *frame, unsigned char *d_MAC, unsigned char *d_IP)
{
	memcpy(frame+0, bro_MAC, 6);
	memcpy(frame+6, d_MAC, 6);
	memcpy(frame+12, ethertype_ARP, 2);
	memcpy(frame+14, HW, 2);
	memcpy(frame+16, PR, 2);
	memcpy(frame+18, LDH, 1);
	memcpy(frame+19, LDP, 1);
	memcpy(frame+20, epcode_ARP_request, 2);

	memcpy(frame+22, d_MAC, 6);
	memcpy(frame+28, d_IP, 4);
	memcpy(frame+32, clear_MAC, 6);
	memcpy(frame+38, d_IP, 4);
}

int BD_MySQL_Find_IP(char *ip)
{
	memcpy(dest_MAC, MAC, 6);

	sprintf(consult, "select * from PC where IP_Address='%s';", ip);

	if((mysql_query(connection, consult) == 0))
	{
		result = mysql_use_result(connection);

		while(row = mysql_fetch_row(result))
			if(sscanf(row[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]) < 6)
				fprintf(stderr, "No es posible la conversion. %s\n", row[2]);
	}
	
	if(!mysql_eof(result))
		printf("Error de lectura %s\n", mysql_error(connection));

	if(!memcmp(MAC, clear_MAC, 6))
	{
		//printf("La IP no esta registrada en la base de datos.\n\n");
		return 0;
	}
	else
	{
		//printf("La IP esta registrada en la base de datos.\n");
		return 1;
	}
}