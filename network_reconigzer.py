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


def main():
    show_interfaces_table()
    #print(psutil.net_io_counters(pernic=True, nowrap=True))
    #print(psutil.net_if_stats()) #Interfaces de Red
    #print(psutil.net_if_addrs())
    #print(psutil.net_connections(kind='inet'))
    



if __name__ == '__main__':
    main()
