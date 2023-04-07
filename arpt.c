  /***************************************************************************
 * arpt.c
 *
 *  Programa principal para probar ARP en las practicas de 
 *  Arquitectura de Redes 2 de la EPS-UAM
 *
 *  Autor: Manuel Freire
 *  Modificado: Manuel Ruiz
 *		Javier Ramos
 *
 *
 *
 *  (C) 2006-14 EPS-UAM 
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "funcs.h"

#include "rc_funcs.h"
#include "arp.h"

#define MAX_LINEA 256 
 
/****************************************************************************
 * Procesa tramas Ethernet entrantes desde el nivel1
 * Copia la trama y, si es procesable, la procesa
 *
 * entra:
 *    tamano - en uint8_ts de toda la trama, incluyendo cabeceras ethernet
 *    trama - los uint8_ts de la trama
 * sale:
 *    0 si todo bien, -1 si error en el procesamiento
 ****************************************************************************/
 int gestionaTramaEthernet(const uint8_t * srcAddr, int tamano, const uint8_t * buffer, uint16_t tipo, const struct timeval * tv);

 int gestionaTramaEthernet(const uint8_t * srcAddr, int tamano, const uint8_t * buffer, uint16_t tipo, const struct timeval * tv)

 {

 

	

  

    // comprueba si es una trama ARP, y en caso afirmativo, la procesa
	
    if (tipo==ethertype_arp) {        

        

       
	
        arp_procesa_trama(srcAddr,tamano,buffer);

    }

        

    return 0;

}

/***************************************************************************
 * "main"
 ***************************************************************************/
int main(int argc, char **argv)
{
  char buffer[MAX_LINEA];
  uint32_t dir_ip;
  uint8_t dir_eth[ETH_ALEN];
  int debug = 0;
  int fin_solicitado = 0;
  int rc;
  
  char *ayuda =
    "Uso: arpt [<nivel_trazas>]\n"
    "  <nivel_trazas> - 0 = sin trazas, 3 = maximo detalle\n";
        
  char *teclas = 
    "Usa:\n"
    "  'a' - enviar una peticion\n"
    "  'c' - mostrar la tabla ARP\n"
    "  'q' - salir\n";    
  
  // trazas
  if (argc > 1) {
    debug = atoi(argv[1]);
    if (argv[1][0] < '0' || argv[1][0] > '9' || debug < 0 || debug > 3) {
        fprintf(stderr,"%s\n", ayuda);
    }
  }

          // inicia el nivel1; no usa 'timeout' para la recepcion
          
    uint16_t tipos[10];  
         
           
	tipos[0]=TYPE1;
	tipos[1]=TYPE2;
	
  if (InicializarEth(tipos,2,gestionaTramaEthernet, 1000) != ETH_OK) {
    fprintf(stderr, "Error en IniciarNivel1\n");
    return -1;
  }

 
  if (arp_inicializa() != 0) {
    fprintf(stderr, "Error en arp_inicializa\n");
    
    return -1;
  }  

  // bucle principal
  printf("ARP-T iniciado; usa 'h' para ver la ayuda.\n");
  while ( ! fin_solicitado) {
    if (fgets(buffer, MAX_LINEA, stdin) == NULL) {
        fin_solicitado = 1;
    }
    else {
        switch (buffer[0]) {
            case 'a': case 'A':
                if (lee_cadena_ip(buffer+2, &dir_ip) != -1) {
                    rc = arp_solicita_direccion(dir_ip, dir_eth);
                    if (rc == -1) {
                        printf("Direccion Eth. no encontrada.\n");
                    }
                    else {
                        printf("Direccion Eth. encontrada: "
                            "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n", 
                            dir_eth[0], dir_eth[1], dir_eth[2],
                            dir_eth[3], dir_eth[4], dir_eth[5]);
                    }
                }
                else {
                    printf("Dir. IP mal escrita; vuelve a intentarlo.\n");
                }
                break;
            case 'c': case 'C':
                arp_muestra_cache();
                break;
            case 'q': case 'Q': case -1:
                fin_solicitado = 1;    
                break;
            case 'h': case 'H':
                printf("%s\n",teclas);
                break;
            case '\n':
                break;
            default:
                printf("No entiendo '%s'. %s", buffer, teclas);
                break;
        }
    }
  }

  arp_finaliza() ;
  if (FinalizarEth() != ETH_OK) {
    printf("Error en FinalizarNivel1a");
    return -1;
  }

  return 0;
}
