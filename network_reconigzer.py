import psutil
from tabulate import tabulate
from serial.tools.list_ports import comports

def show_interfaces_table():
    print("Obteniendo interfaces de red...")
    interfaces_status =psutil.net_if_stats()
    interfaces =psutil.net_if_addrs()
    pack = psutil.net_io_counters(pernic=True, nowrap=True)
    table = []
    table2 = []
    headers = [ 'Interfaz', 'Estatus', 'Direccion', 'Familia', 'Mascara de Red', 'Paquetes enviados', 'Paquetes recibidos' ]
    for key in interfaces_status:
        interface = str(key)
        family = interfaces[interface][0].family.name
        address = interfaces[interface][0].address
        mask = interfaces[interface][0].netmask
        sent = pack[interface].packets_sent
        recv = pack[interface].packets_recv
        is_active = 'inactiva'
        if (interfaces_status[key].isup):
            is_active = 'activa'
        table.append([interface, is_active, address, family, mask, sent, recv ])
    
    print(tabulate(table, headers, tablefmt="rounded_grid"))


def show_conections_table():
    tcp = psutil.net_connections(kind='all')
    print("Obteniendo conexiones de red...")
    table = []
    headers = ['Direccion Local', 'Puerto Local', 'Direccion Destino', 'Puerto Destino', 'ID Proceso', 'Estatus'  ]
    for conection in tcp:
        try:

            laddr = conection.laddr.ip
            lport = conection.laddr.port
            raddr = conection.raddr.ip
            rport = conection.raddr.port
            pid = conection.pid
            status = conection.status
            table.append([ laddr, lport, raddr, rport, pid, status ])
        except:
            pass
    print(tabulate(table, headers, tablefmt="rounded_grid"))
        
        
        

def main():
    show_interfaces_table()
    show_conections_table()
    #print(psutil.net_io_counters(pernic=True, nowrap=True))
    #print(psutil.net_if_stats()) #Interfaces de Red
    #print(psutil.net_if_addrs())
    #print(psutil.net_connections(kind='inet'))
    



if __name__ == '__main__':
    main()
    input("\n\nPRESIONE ENTER PARA FINALIZAR ")
