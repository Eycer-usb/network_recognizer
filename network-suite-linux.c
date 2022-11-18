// Utilidades
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>

// NIC
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h> 

// Mensajes kernel para sockets
#include <linux/sock_diag.h>
#include <linux/inet_diag.h> /* for IPv4 and IPv6 sockets */
#include <linux/netlink.h>
#include <sys/socket.h>

// Mensajes kernel para enrutamiento
#include <linux/rtnetlink.h>

// Constantes
#include <limits.h>

#define MAC_ADDR_LEN 24
#define BIG_BUFFER (8192 / sizeof(long))
#define TRUE (1 == 1)
#define FALSE (!TRUE)

#define NIC_OPT 1
#define IP4_TBL 2
#define IP6_TBL 3
#define GTW_OPT 4
#define EXIT_PR 5

/// @brief Revisa si string es un numero.
/// @param str String a revisar
/// @return TRUE si es numero.
int is_number(char *str);

/// @brief Limpia buffer de input.
void clear_input();

/// @brief Imprime el menu de opciones
void print_menu();

/// @brief Obtiene toda la informacion de las interfaces de red.
void get_all_interfaces_info();

/// @brief Hace print a las interfaces de red IPv4 o IPv6
/// @param nic Estructura de la interfaz de red.
/// @param sock_addr Estructura con informacion de la direccion de la interfaz.
void print_ip_interface_info(struct ifaddrs* nic, struct sockaddr* sock_addr);

/// @brief Hace print a la direccion fisica de las interfaces
/// @param nic Estructura de la interfaz de red.
void print_mac_interface_info(struct ifaddrs* nic);

/// @brief Examina el status de una interfaz de red y devuelve un string 
/// identificando el estado.
/// @param status Estado de la interfaz
/// @return String con estado
char* get_interface_status_name(unsigned int status);

/// @brief Hace display a la informacion de los sockets de red con protocolos
/// IPv4 o IPv6
/// @param fam Familia de la direccion. AF_INET o AF_INET6
void get_ip_socket_info(int fam);

/// @brief Solicita informacion al kernel sobre los sockets de red con protocolos
/// IP
/// @param sockfd FD del socket con el cual se realiza la peticion
/// @param fam Familia de la direccion. AF_INTET o AF_INET6
/// @param prot Protocolo del socket. IPPROTO_TCP O IPPROTO_UDP.
void request_ip_socket(int sockfd, int fam, int prot);

/// @brief Recive informacion al kernel sobre los sockets de red con protocolos
/// IP
/// @param fd FD del socket con el cual se realiza la peticion
/// @param fam Familia de la direccion. AF_INTET o AF_INET6
/// @param prot Protocolo del socket. IPPROTO_TCP O IPPROTO_UDP.
void receive_ip_socket_resp(int fd, int fam, int prot);

/// @brief Extrae e imprime informacion de la respuesta recibida del kernel sobre
/// los sockets de red.
/// @param resp Respuesta recibida
/// @param len Largo de la respuesta
/// @param prot Protocolo de los sockets. IPPROTO_TCP O IPPROTO_UDP.
void print_ip_socket(struct inet_diag_msg* resp, unsigned int len, int prot);

void get_gateway_info();
void request_routes(int sockfd);
void receive_route(int sockfd);


int main(int argc, char const *argv[])
{ 
    char inputstr[4];
    int inputint;
    for (;;clear_input())
    {
        print_menu();
        printf("OPCION > ");
        if (fgets(inputstr, 2, stdin) == NULL)
        {
            printf("Problema con el input recibido.\n");
            return 0;
        }

        inputstr[strcspn(inputstr, "\n")] = '\0';
        if (!is_number(inputstr))
        {
            printf("Por favor, introduzca una opcion del menu.\n");
            continue;
        }

        inputint = atoi(inputstr);
        switch (inputint)
        {
        case NIC_OPT:
            printf("\n");
            get_all_interfaces_info();
            break;
        case IP4_TBL:
            printf("\nTabla conexiones IPv4:\n");
            get_ip_socket_info(AF_INET);
            break;
        case IP6_TBL:
            printf("\nTabla de conexion es IPv6:\n");
            get_ip_socket_info(AF_INET6);
            break;
        case GTW_OPT:
            printf("\nRutas hacia el gateway:\n");
            get_gateway_info();
            break;;
        case EXIT_PR:
            return EXIT_SUCCESS;
        default:
            printf("Por favor, introduzca una opcion del menu.\n");
            break;
        }
        printf("\n");
        continue;
    }
    
    return EXIT_SUCCESS;
}


int is_number(char *str)
{
    for (char c; (c = *str) != '\0';  ++str)
    {
        if (!isdigit(c))
            return FALSE;
    }

    return TRUE;
}


void clear_input()
{
    for (int c;(c = getchar()) != '\n' && c != EOF;);
};


void print_menu()
{
    printf("OPCIONES:\n");
    printf("1) Interfaces de red\n");
    printf("2) Conexiones IPv4\n");
    printf("3) Conexiones IPv6\n");
    printf("4) Rutas Gateway\n");
    printf("5) Salir\n");
}


void get_all_interfaces_info()
{
    struct ifaddrs* lls;
    if (!getifaddrs(&lls) == -1)
        return;

    printf("Interfaces de red:\n");
    printf("%20s %15s %13s %24s\n", "NAME", "STATUS", "ADDRESS TYPE", "ADDRESS");
    for (; lls != NULL; lls = lls->ifa_next)
    {
        struct sockaddr* sock_addr = lls->ifa_addr;
        if (sock_addr == NULL)
            continue;

        int af = sock_addr->sa_family;
        if (af == AF_INET || af == AF_INET6)
        {
            print_ip_interface_info(lls, sock_addr);
            continue;
        }

        if (af != AF_PACKET)
            continue;;

        print_mac_interface_info(lls);
    }
    freeifaddrs(lls);
}


void print_ip_interface_info(struct ifaddrs* nic, struct sockaddr* sock_addr)
{
    printf("%20s %15s", nic->ifa_name, get_interface_status_name(nic->ifa_flags));

    char ipstr[INET6_ADDRSTRLEN + 2];
    void *info;
    int af = sock_addr->sa_family;

    socklen_t addrlen;
    if (sock_addr->sa_family == AF_INET)
    {
        struct sockaddr_in *ip4_addr = (struct sockaddr_in*)sock_addr;
        info = (void *)&(ip4_addr->sin_addr);
        addrlen = INET_ADDRSTRLEN;
    }
    else if (sock_addr->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *ip6_addr = (struct sockaddr_in6*)sock_addr;
        info = (void *)&(ip6_addr->sin6_addr);
        addrlen = INET6_ADDRSTRLEN;
    }

    inet_ntop(af, info, ipstr, addrlen);
    printf(" %13s: %24s\n", "IP ADDRESS", ipstr);
}


void print_mac_interface_info(struct ifaddrs* nic)
{
    printf("%20s %15s", nic->ifa_name, "MAC NIC");
    char macstr[MAC_ADDR_LEN] = "";

    struct sockaddr_ll *s = (struct sockaddr_ll*)nic->ifa_addr;
    for (int i=0; i < s->sll_halen; i++)
    {
        char tmp[MAC_ADDR_LEN];
        sprintf(tmp, "%02x%c", (s->sll_addr[i]), (i+1!=s->sll_halen)?':': '\0');
        strcat(macstr, tmp);
    }
    printf(" %13s: %24s\n", "MAC", macstr);
}


char* get_interface_status_name(unsigned int status)
{
    static char status_str[16] = "";
    if ((status & IFF_UP) && (status & IFF_RUNNING == 0))
    {
        strcpy(status_str, "UP");
        return status_str;
    }  
    else if (status & IFF_LOOPBACK)
    {
        strcpy(status_str, "LOOPBACK");
        return status_str;
    } 
    else if (status & IFF_RUNNING)
    {
        strcpy(status_str, "RUNNING");
        return status_str;
    }
    else if (status & IFF_BROADCAST)
    {
        strcpy(status_str, "BROADCAST");
        return status_str;
    }
    else if (status & IFF_DEBUG)
    {
        strcpy(status_str, "DEBUG");
        return status_str;
    }
    else if ((status & IFF_UP == 0) && (status & IFF_RUNNING == 0))
    {
        strcpy(status_str, "DOWN");
        return status_str;
    }

    strcpy(status_str, "NO INFO");
    return status_str;
}

void print_ip_socket(struct inet_diag_msg* resp, unsigned int len, int prot)
{
    if (len < NLMSG_LENGTH(sizeof(*resp))) {
        fputs("Respuesta de largo incorrecto\n", stderr);
        return;
    }

    char local_buff[INET6_ADDRSTRLEN + 12];
    char remot_buff[INET6_ADDRSTRLEN + 12];
    char local_buff2[INET6_ADDRSTRLEN + 12];
    char remot_buff2[INET6_ADDRSTRLEN + 12];
    struct inet_diag_sockid sockid = resp->id;
    
    if (resp->idiag_family == AF_INET)
    {
        inet_ntop(AF_INET, (struct in_addr*) &(resp->id.idiag_src), 
            local_buff, INET_ADDRSTRLEN);

        inet_ntop(AF_INET, (struct in_addr*) &(resp->id.idiag_dst), 
            remot_buff, INET_ADDRSTRLEN);
    }
    else if (resp->idiag_family == AF_INET6)
    {
        inet_ntop(AF_INET, (struct in6_addr*) &(resp->id.idiag_src), 
            local_buff, INET6_ADDRSTRLEN);

        inet_ntop(AF_INET, (struct in6_addr*) &(resp->id.idiag_dst), 
            remot_buff, INET6_ADDRSTRLEN);  
    }
    
    sprintf(local_buff2, "%s:%hu", local_buff, htons(resp->id.idiag_sport));
    sprintf(remot_buff2, "%s:%hu", remot_buff, htons(resp->id.idiag_dport));

    if (prot == IPPROTO_TCP)
        printf("%9s %30s %30s\n", "TCP", local_buff2, remot_buff2);
    else if (prot == IPPROTO_UDP)
        printf("%9s %30s %30s\n", "UDP", local_buff2, remot_buff2);
    else
        printf("Protocolo invalido"); 

}

void get_ip_socket_info(int fam)
{
    // Abrimos socket para realizar la comunicacion
    int diag_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    if (diag_socket < 0)
    {
        printf("Error creando socket de comunicacion de sockets.");
        return;
    }

    request_ip_socket(diag_socket, fam, IPPROTO_TCP);
    receive_ip_socket_resp(diag_socket, fam, IPPROTO_TCP);

    request_ip_socket(diag_socket, fam, IPPROTO_UDP);
    receive_ip_socket_resp(diag_socket, fam, IPPROTO_UDP);
    close(diag_socket);
}


void request_ip_socket(int sockfd, int fam, int prot)
{
    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK
    };

    struct 
    {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 inr;
    } req = {
        .nlh = {
            .nlmsg_len = sizeof(req),
            .nlmsg_type = SOCK_DIAG_BY_FAMILY,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP
        },
        .inr = {
            .sdiag_family = fam,
            .sdiag_protocol = prot,
            .idiag_states = 0xFFF, //12 estados posibles.
            .idiag_ext = INET_DIAG_INFO
        }
    };
    
    struct iovec iov = {
        .iov_base = &req,
        .iov_len = sizeof(req)
    };
    
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    for (;;) 
    {
        if (sendmsg(sockfd, &msg, 0) < 0) 
        {
            if (errno == EINTR)
                continue;
            
            printf("Error del kernel enviando mensaje.\n");
            return;
        }
        return;
    }
}


void receive_ip_socket_resp(int fd, int fam, int prot)
{
    long buf[BIG_BUFFER];

    struct sockaddr_nl nladdr;
    struct iovec iov = {
        .iov_base = buf,
        .iov_len =  sizeof(buf)
    };

    for (;;) 
    {
        struct msghdr msg = {
            .msg_name = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov = &iov,
            .msg_iovlen = 1    
        };

        ssize_t ret = recvmsg(fd, &msg, 0);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;

            printf("Error del kernel recibiendo mensaje.\n");
            return;
        }
        if (ret == 0)
            return;

        if (nladdr.nl_family != AF_NETLINK)
        {
            printf("Mensaje recibido de tipo erroneo.\n.");
            return;
        }

        const struct nlmsghdr *h = (struct nlmsghdr *) buf;
        if (!NLMSG_OK(h, ret))
        {
            printf("Mensaje recibido con problemas\n");
            return;
        }

        if (NLMSG_OK(h, ret) && h->nlmsg_type == NLMSG_DONE) // Pendiente con esto
            return;

        printf("%9s %30s %30s\n", "PROTOCOL", "SRC ADDR", "DST ADDR");
        for (;NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret))
        {
            if (h->nlmsg_type == NLMSG_DONE)
                return;

            if (h->nlmsg_type == NLMSG_ERROR)
            {
                printf("Error en lectura de mensajes\n");
                return;
            }

            print_ip_socket(NLMSG_DATA(h), h->nlmsg_len, prot);   
        }
        return;
    }
}


void get_gateway_info()
{
    // Abrimos socket para realizar la comunicacion
    int diag_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (diag_socket < 0)
    {
        printf("Error creando socket de comunicacion de rutas.");
        return;
    }

    request_routes(diag_socket);
    receive_route(diag_socket);
    close(diag_socket);
}


void request_routes(int sockfd)
{
    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK
    };

    struct {
        struct nlmsghdr nlhdr;
        struct rtmsg rtmsg;
    } req = {
        .nlhdr = {
            .nlmsg_type = RTM_GETROUTE,
            .nlmsg_len = sizeof(req),
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP
        },
        .rtmsg = {
        }
    };

    struct iovec iov = {
        .iov_base = &req,
        .iov_len = sizeof(req)
    };
    
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    for (;;) 
    {
        ssize_t sent = sendmsg(sockfd, &msg, 0);
        if (sent < 0) 
        {
            if (errno == EINTR)
                continue;
            
            printf("Error del kernel enviando mensaje.\n");
            return;
        }
        break;
    }
}


void receive_route(int sockfd)
{
    long buf[BIG_BUFFER];

    struct sockaddr_nl nladdr;
    struct iovec iov = {
        .iov_base = buf,
        .iov_len =  sizeof(buf)
    };

    for (;;) 
    {
        struct msghdr msg = {
            .msg_name = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov = &iov,
            .msg_iovlen = 1    
        };

        ssize_t ret = recvmsg(sockfd, &msg, 0);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;

            printf("Error del kernel recibiendo mensaje.\n");
            return;
        }
        if (ret == 0)
            return;

        if (nladdr.nl_family != AF_NETLINK)
        {
            printf("Mensaje recibido de tipo erroneo.\n.");
            return;
        }

        const struct nlmsghdr *h = (struct nlmsghdr *) buf;
        if (!NLMSG_OK(h, ret))
        {
            printf("Mensaje recibido con problemas\n");
            return;
        }

        printf("%20s %24s %24s %24s\n", "NIC NAME", "SOURCE", "DEST", "GTW");
        for (;NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret))
        {
            if (h->nlmsg_type == NLMSG_DONE)
                return;

            if (h->nlmsg_type == NLMSG_ERROR)
            {
                printf("Error en lectura de mensajes\n");
                return;
            }

            struct rtmsg* msg = (struct rtmsg *)NLMSG_DATA(h);
            struct rtattr* rtAttr;
            int rtlen = RTM_PAYLOAD(h);

            if((msg->rtm_family != AF_INET))
                return;

            rtAttr = (struct rtattr *)RTM_RTA(msg);
            struct in_addr dstAddr;
            struct in_addr srcAddr;
            struct in_addr gateWay;
            char ifName[IF_NAMESIZE];
            int addrstrlen = (msg->rtm_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);

            for (;RTA_OK(rtAttr, rtlen); rtAttr = RTA_NEXT(rtAttr, rtlen))
            {
                switch (rtAttr->rta_type)
                {
                    case RTA_OIF:
                      if_indextoname(*(int *)RTA_DATA(rtAttr), ifName);
                      break;

                    case RTA_GATEWAY:
                      memcpy(&gateWay, RTA_DATA(rtAttr), sizeof(dstAddr));
                      break;

                    case RTA_PREFSRC:
                      memcpy(&srcAddr, RTA_DATA(rtAttr), sizeof(srcAddr));
                      break;

                    case RTA_DST:
                      memcpy(&dstAddr, RTA_DATA(rtAttr), sizeof(gateWay));
                      break;
                }
            }

            char remot_buff[64];
            char src_buff[64];
            char gtw_buff[64];

            inet_ntop(msg->rtm_family, &(srcAddr.s_addr), src_buff, addrstrlen); 
            inet_ntop(msg->rtm_family, &(dstAddr.s_addr), remot_buff, addrstrlen); 
            inet_ntop(msg->rtm_family, &(gateWay.s_addr), gtw_buff, addrstrlen); 

            printf("%20s %24s %24s %24s\n", ifName, src_buff, remot_buff, gtw_buff);
        }
        return;
    }
}