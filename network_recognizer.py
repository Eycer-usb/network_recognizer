import psutil
from tabulate import tabulate
from serial.tools.list_ports import comports


def get_nic_info(key, name, nic_info, nics_status, pack_info):
    nic_entries = []
    is_active = ('activa' if nics_status else 'inactiva')
    for nent in nic_info:
        try:
            nic_entries.append([name, is_active, nent.address, nent.family.name, nent.netmask, 
                pack_info[key].packets_sent, pack_info[key].packets_recv])
        except AttributeError:
            nic_entries.append([name, is_active, nent.address, 
                nent.family.name, nent.netmask, None, None])

    return nic_entries


def show_interfaces_table():
    print("Obteniendo interfaces de red...")
    interfaces_status =psutil.net_if_stats()
    interfaces =psutil.net_if_addrs()
    pack = psutil.net_io_counters(pernic=True, nowrap=True)
    table = []
    headers = [ 'Interfaz', 'Estatus', 'Direccion', 'Familia', 'Mascara de Red', 'Paquetes enviados', 'Paquetes recibidos' ]
    for key in interfaces_status:
        nic_name = str(key)
        is_active = interfaces_status[key].isup
        info = get_nic_info(key, nic_name, interfaces[nic_name], is_active, pack)
        for entry in info:
            table.append(entry)
    
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


if __name__ == '__main__':
    main()
    input("\n\nPRESIONE ENTER PARA FINALIZAR ")
