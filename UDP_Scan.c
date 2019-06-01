#include "comnet.c"

int main(int argc, char const *argv[])
{
	int packet_socket, index;

	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(packet_socket == -1)
	{
		perror("Error al abrir el socket");
		exit(1);
	}
	else
	{
		perror("Exito al abrir el socket");
		index = getData(packet_socket);
		
        
		
	}
	
	close(packet_socket);
	return 1;
}