#include "nivelEth.h"
#include <pthread.h>
#include "rc_funcs.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#define DIM 2048
#define INTERFACE "enp4s0"

/******************************
*Arquitectura de Redes II     *
*Funciones de Nivel Ethernet  *
*Javier Ramos 2013-2014       *
* Manuel Ruiz 2017-2018       *
*******************************/


pthread_t t;
pcap_t  *p;

//Declaraciones Auxiliares
uint8_t macaddrpkt[6];
uint8_t tamTypes;
uint16_t Tipos[5];
int timeout, InicializarNivel1a;
tpfNotificacionRecepcionEth func;


/************************************************************************************************
*Funcion:getMACAddr 									                                     	*
*Descripcion: Obtiene la direccion MAC de una interfaz						                    *
*Entrada:											                                            * 
*	mac:vector de 6 bytes a rellenar con la MAC de la interfaz				                    *
*	interface: nombre la de interfaz de la cual se obtendra la MAC. Por ejemplo "eth0"	        *
*Retorno: Ninguno										                                        *
*************************************************************************************************/

void getMACAddr(uint8_t *mac,char *interface)
{
    
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(mac,ifr.ifr_hwaddr.sa_data,HWADDR_len);
  
}
/************************************************************************************************
*Funcion:attendPacket										*
*Descripcion: Esta funcion se ejecuta cada vez que se recibe un paquete. Aqui dentro debe	*
*	      ejecutarse cualquier operación sobre el paquete recibido				*
*Entrada:											* 
*	user:informacion pasada a nivel de usuario por la libreria pcap (desde pcap_loop)	*
*	h: esructura de cabecera pcap del paquete recibido (tiempo y tamanyo)			*
*	packet: buffer con el contenido binario del paquete					*
*Retorno: Ninguno										*
*************************************************************************************************/

void attendPacket(u_char *user,const struct pcap_pkthdr *h,const u_char *packet)
{
	/**PRACTICA Implementar aquí las acciones necesarias al recibir un paquete*/
//	
	//Declaracion variables necesarias
	int pkt = 0;
	uint8_t MACAddr[6], MACAddrOrigen[6];
	uint16_t packetType, READType; //Creamos READType para pasar de la lectura en &READType a la variable packetType
	uint32_t sizeRead = 0;
	u_char mensaje[DIM];
	uint32_t CRCpkt;
	//EO Declaraciones
	

	//printf("attendPacket\n");
	//printf("attending package numero: %d\n", pkt);
	pkt++;

	//Asignaciones
	memcpy(MACAddr, packet+sizeRead, ETH_ALEN * sizeof (uint8_t));
	sizeRead+= ETH_ALEN * sizeof (uint8_t);
	
	memcpy(MACAddrOrigen, packet+sizeRead, ETH_ALEN * sizeof (uint8_t));
	sizeRead+= ETH_ALEN * sizeof (uint8_t);
	
	memcpy(&READType, packet+sizeRead, ETH_TLEN * sizeof(uint8_t));
	packetType = htons(READType);
	sizeRead+= ETH_TLEN * sizeof(uint8_t);
	//Para pasar de formato a Red, utilizamos htons :)
	
	memcpy(mensaje, packet+sizeRead, (h->len)-sizeRead);
	sizeRead+= h->len;
	//tamanyoMenasje = h->len - tamanyo cabecera


	if(packetType != TYPE1 && packetType != TYPE2){
	//	printf("El type no coincide.");
		return;
	}
	else{
	//printf("El Type coincide.");
	uint32_t tamanyopkt;
	tamanyopkt = (h->len) - sizeRead;
	func(MACAddrOrigen, tamanyopkt, mensaje, packetType, &h->ts);
	}
	

}


/************************************************************************************************
*Funcion:startCapture										*
*Descripcion: Esta funcion se ejecuta en un hilo nuevo e inicia la captura de paquetes a	*
*	      través de la función pcap_loop. Se ejecuta en un nuevo hilo parta evitar que el 	*
*	      programa principal quede bloqueado al llamar a la función InicializarNivel1a	*
*Entrada:											* 
*	arg: argumentos del hilo. En nuestro caso ninguno					*
*Retorno: Ninguno										*
*************************************************************************************************/
void * startCapture(void *arg)
{
	pcap_loop(p,-1,attendPacket,NULL);
}
/************************************************************************************************
*Funcion:InicializarStackRed							*
*Descripcion: Esta funcion inicia el nivel1a registrando la función de notificación, abriendo 	*
*	      una captura live pcap y lanzando un hilo de proceso de paquetes			*
*												*
*************************************************************************************************/
int InicializarEth(uint16_t *Tipos, uint8_t nType, tpfNotificacionRecepcionEth funcion, int timeout)
{
	char errbuff[1000];
	/**PRACTICA Implementar aquí las acciones necesarias para inciar el nivel Ethernet*/
//	printf(" IMPLEMENTAR InicializarEth\n");
	for(int i=0; i<nType; i++){
	Tipos[i] = Tipos[i];
	tamTypes = nType;
	}
	
	getMACAddr(macaddrpkt, INTERFACE); //He sacado eth0 de la interfaz ya que la de mi Mac es wlp2s0, lo mismo en la funcion de abajo 	
 	func = funcion;
	
	p = pcap_open_live(INTERFACE, ETH_MAX_LEN, 1, timeout, errbuff); //abre en modo promiscuo
	
	if (p == NULL){
		printf ("Error: %s\n", errbuff); //el error se guarda en errbuff
		return ETH_ERROR;
	}
	
	if(func != 0){
	pthread_create(&t,NULL,startCapture,NULL);
	}
	
	InicializarNivel1a = ETH_OK;

	return ETH_OK;
	
}

/************************************************************************************************
*Funcion:FinalizarEth							*
*Descripcion: Esta funcion finaliza el nivel1a liberando los recursos que se hayan reservado y 	*
*	      cerrando la captura live pcap							*
*												*
*************************************************************************************************/
int FinalizarEth(void){

	/**PRACTICA Implementar aquí las acciones necesarias para finalizar el nivel Ethernet*/
	
	if (InicializarNivel1a==1){
            pcap_breakloop(p);
            pcap_close(p);
            return ETH_OK;
        }
        else{
            printf("Error en nivel ETH");
            return -1;
        }
	
	return 0;
}

/************************************************************************************************
*Funcion:EnviarDatagramaEth									*
*Descripcion: Esta funcion anyade una cabecera Ethernet y el CRC al mensaje pasado 		*
*             como argumento y lo envía utilizando la funcion pcap_inject			*
*												*
*************************************************************************************************/

int EnviarDatagramaEth(const uint8_t *direccion_destino, const  uint8_t *mensaje, uint16_t tamano, uint16_t tipo){

/**PRACTICA Implementar aquí las acciones necesarias para enviar un paquete*/
	//printf("IMPLEMENTAR EnviarDatagramaEth\n");
	
u_char buffer[2000] = {0};
int inject;
uint32_t size = 0;
uint16_t tipo1;



	if (InicializarNivel1a == 1) {
	    memcpy(buffer + size, direccion_destino, 6 * sizeof(uint8_t));
	    size += 6 * sizeof(uint8_t);
	    memcpy(buffer + size, macaddrpkt, 6 * sizeof(uint8_t));
	    size += 6 * sizeof(uint8_t);
	    tipo1 = htons(tipo);
	    memcpy(buffer + size, &tipo1, 2 * sizeof(uint8_t));
	    size += 2 * sizeof(uint8_t);
	    memcpy(buffer + size, mensaje, tamano);
     	    size += tamano;
     	   
     	   
    inject = pcap_inject(p, buffer, size);
    if (inject == -1) {
        printf("ERROR en el envio de la trama\n\n");
        return ETH_ERROR;
    }
    else {
        printf("Trama enviada correctamente\n\n");
        return ETH_OK;
    }
	} else{
	    return ETH_ERROR;
	}


}
