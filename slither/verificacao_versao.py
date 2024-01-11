import os
import re

def verifica_versao(_path=''):

    path = _path

    #pegar lista de arquivos
    arquivos = os.listdir(path)

    for arquivo in arquivos:

        with open(f'{path}{arquivo}', 'r') as arquivo:
            conteudo = arquivo.read()
        

            expressao_regular = r'pragma solidity (.+?);'

            resultado = re.search(expressao_regular, conteudo)

            if resultado:
                ret = resultado.group(1)
                print(ret)
            else:
               pass 



if '__main__'==__name__:

    verifica_versao('./smartbugs-curated/')


