import os
import subprocess

caminho_do_diretorio = r'.\\verified-smart-contracts-database\\verified-smart-contracts'  # Substitua pelo caminho do diretório desejado

# Listar arquivos no diretório
arquivos = os.listdir(caminho_do_diretorio)

# Exibir os nomes dos arquivos
for arquivo in arquivos:
    comando_slither = [
        'slither',
        f'./verified-smart-contracts-database/verified-smart-contracts/{arquivo}',
        '--json',
        f'{arquivo}.json'
    ]
    resultado = subprocess.run(comando_slither, capture_output=True, text=True)
    # with open(f'{arquivo}.json', 'a') as arquivo:
    #     arquivo.write(str(resultado))
    #     # Você pode adicionar mais linhas conforme necessário