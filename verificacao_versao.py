import os
import re
import pandas as pd

def verifica_versao(_path=''):

    path = _path

    #pegar lista de arquivos
    arquivos = os.listdir(path)
    lista_versao = []
    for arquivo in arquivos:

        with open(f'{path}{arquivo}', 'r') as arquivo:
            conteudo = arquivo.read()
        

            expressao_regular = r'pragma solidity (.+?);'

            resultado = re.search(expressao_regular, conteudo)

            if resultado:
                versao = resultado.group(1)
                lista_versao.append(versao)
                print(versao)
            else:
               versao = 0 
               lista_versao.append(versao)

    data = {'Arquivos':arquivos,'Versão':lista_versao}      
    df=pd.DataFrame(data)
    print(df)  
    nome = path.split("/")[-2]
    
    df.to_excel(f'{nome}_versao.xlsx')  

if '__main__'==__name__:

    verifica_versao('./smartbugs-curated/')


