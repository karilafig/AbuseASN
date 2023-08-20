import requests
import datetime
import re
import subprocess
import json
import urllib3

print('''
                                                                                                                                                  
              ,,                                                                         
      db     *MM                                        db       .M"""bgd `7MN.   `7MF'   
     ;MM:     MM                                       ;MM:     ,MI    "Y   MMN.    M    
    ,V^MM.    MM,dMMb.`7MM  `7MM  ,pP"Ybd  .gP"Ya     ,V^MM.    `MMb.       M YMb   M    
   ,M  `MM    MM    `Mb MM    MM  8I   `" ,M'   Yb   ,M  `MM      `YMMNq.   M  `MN. M    
   AbmmmqMA   MM     M8 MM    MM  `YMMMa. 8M""""""   AbmmmqMA   .     `MM   M   `MM.M    
  A'     VML  MM.   ,M9 MM    MM  L.   I8 YM.    ,  A'     VML  Mb     dM   M     YMM    
.AMA.   .AMMA.P^YbmdP'  `Mbod"YML.M9mmmP'  `Mbmmd'.AMA.   .AMMA.P"Ybmmd"  .JML.    YM    
                                                                                                                                                                                                                                      
''')



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_ips_with_netmask(output):
    # Regex para extrair os IPs com máscara de rede
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/(?:[0-9]{1,2}))?\b')
    ips = ip_pattern.findall(output)
    return ips

def get_ips_from_asn(asns):
    ips_list = []

    for asn in asns:
        # Executar o comando Nmap para varrer os hosts do ASN
        command = f'nmap --script targets-asn --script-args targets-asn.asn={asn}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)


        ips = extract_ips_with_netmask(result.stdout)
        ips_list.extend(ips)

    return ips_list

def execute_nmap_for_ip_range(ip_range):
    # Executar o comando nmap -sL -n 
    command = f'nmap -sL -n {ip_range}'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Filtrar e extrair apenas os endereços IP
    ip_pattern = re.compile(r'for\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)')
    ips = ip_pattern.findall(result.stdout)
    return ips

def get_ip_info_from_abuseipdb(ip, api_key):
    base_url = f"https://api.abuseipdb.com/api/v2/check"

    # Parâmetros da solicitação
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",  
        "verbose": "yes",  
    }

    
    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    # Faz a solicitação à API do AbuseIPDB
    response = requests.get(base_url, params=params, headers=headers, verify=False)

    # Verifica a resposta
    if response.status_code == 200:
        data = response.json()
        if data.get("data") and data["data"].get("abuseConfidenceScore") > 0:
            return data["data"]
    else:
        print(f"Erro ao verificar o IP {ip}: {response.text}")

    return None

if __name__ == '__main__':
    api_key = input("Digite a sua chave da API do AbuseIPDB: ")

    asn = input("Insira o ASN que você deseja verificar (para mais de um ASN, separe por virgula): ")

    # Dividir o input do usuário em uma lista de ASNs (caso o usuário insira vários separados por vírgula)
    target_asns = asn.split(',')

    ips = get_ips_from_asn(target_asns)

    if len(ips) > 0:
        for ip_range in ips:
            ip_list = execute_nmap_for_ip_range(ip_range)
            found_reports = False
            for ip in ip_list:
                ip_info = get_ip_info_from_abuseipdb(ip, api_key)
                if ip_info:
                    print(f"IP: {ip_info['ipAddress']}, Country: {ip_info['countryCode']}, Reports: {ip_info['totalReports']}")
                    found_reports = True  # Relatórios foram encontrados neste bloco de IPs

            if not found_reports:
                print(f"Nenhum relatório encontrado para o bloco de IPs {ip_range}.")
    else:
        print("Nenhum IP associado encontrado para o ASN informado.")
