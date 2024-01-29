import re
import subprocess
import os
import json
import pandas as pd

class SmartToolsAnalysis():
    
    solc =''
    solc_dic = {'4':'0.4.26','5':'0.5.17','6':'0.6.12','7':'0.7.6','8':'0.8.23'}
    solc_numero ='' 

    def __init__(self,_solc='') -> None:

        self.set_solc(_solc)
        self.solc = _solc
        self.solc_numero = _solc.split('.')[1]

    def set_solc(self,_solc):

        result = subprocess.run(f'solc-select use {_solc}', capture_output=True, text=True,shell=True)
        print(result)
        return result

    def verificar_pragma(self,file_path):

        #Abri o sol
        with open(file_path, 'r') as arquivo:
            
            conteudo = arquivo.read()
            #monta expressão regular
            expressao_regular = r'pragma solidity\s*\^\s*\d\.(\d)'
            #a retira o valor
            resultado = re.search(expressao_regular, conteudo)

            print(resultado)

            if resultado:
                versao = resultado.group(1)
                numero = versao
                
                if(numero==self.solc_numero):
                    print('Mesma versão de solc')
                else:
                    self.set_solc(self.solc_dic[numero])
                    self.solc = self.solc_dic[numero]
                    self.solc_numero = numero


            else:
                print('Não pegou pragma')

    def create_directory(self,_diretorio):

        diretorio = _diretorio

        # Verifica se o diretório não existe
        if not os.path.exists(diretorio) and _diretorio!='' :
            # Cria o diretório se não existir
            os.makedirs(diretorio)
            print(f'Diretório "{diretorio}" criado com sucesso.')
        else:
            print(f'O diretório "{diretorio}" já existe.')


    def montar_dataframe_json(self,diretory_in,diretory_out):

        #Criar os diretórios caso não existam e seja necessário
        self.create_directory(diretory_in)
        self.create_directory(diretory_out)
        
        json_file = open(f'{diretory_in}data.json')
        lista_sol = json.load(json_file)

        contagem_vulnerabilidades = {}

        for arquivo in lista_sol:
            nome_arquivo = arquivo["nome"]
            vulnerabilidades = arquivo["vulnerabilidades"]

            contagem = {}
            for vulnerabilidade in vulnerabilidades:
                if vulnerabilidade not in contagem:
                    contagem[vulnerabilidade] = 1
                else:
                    contagem[vulnerabilidade] += 1

            contagem_vulnerabilidades[nome_arquivo] = contagem

        # Criar um DataFrame do pandas a partir do dicionário
        df = pd.DataFrame(contagem_vulnerabilidades).fillna(0).astype(int)

        # Visualizar o DataFrame resultante
        dt =df.transpose()
        dt.to_excel(f'{diretory_out}resultado.xlsx')
        return df.transpose()
    
 

    def soma_dataframe(self,df,arquivo):

        # Criar um novo DataFrame com a soma total de cada vulnerabilidade
        soma_total_vulnerabilidades = df.sum(axis=0).reset_index()
        soma_total_vulnerabilidades.columns = ['Vulnerabilidade', 'Soma_Total']

        # Ordenar o DataFrame pela coluna 'Soma_Total' em ordem decrescente
        soma_total_vulnerabilidades = soma_total_vulnerabilidades.sort_values(by='Soma_Total', ascending=False)

        # Visualizar o DataFrame resultante
        soma_total_vulnerabilidades.to_excel(f'{arquivo}_soma.xlsx')

