import os
import subprocess
import pandas as pd
import json
import sys
from IPython.display import display
import openpyxl
import time
import re


class SlitherAnalysis:

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

    #Buscar os arquivos e rodar o slither
    def run_analysis_diretory(self,diretory_in,diretory_out=''):
        
        start_time = time.time()
        # Listar arquivos no diretório
        files = os.listdir( diretory_in)

        # criar diretorio principal
        self.create_directory(diretory_out)
        self.create_directory(diretory_out+'json/')
        self.create_directory(diretory_out+'results/')
        
        #Contagem de erro
        error_count = 0
        # Exibir os nomes dos arquivos
        for file in files:
            

            pragma = self.verificar_pragma (f'{diretory_in}{file}')

            result= subprocess.run(f'slither  {diretory_in}{file} --json {diretory_out}json/{file}.json', capture_output=True, text=True,shell=True)
            
            print(result.args)
            print(result.stdout)

            #Salvando o resultado do json se result não for vazio
            if (result.stdout!=''):
                with open(f'{diretory_out}json/{file}.json', 'w') as arquivo:
                    arquivo.write(result.stdout)
            
            #Verificando se o comando falhou
            if ('warnings/errors' in str(result)):
                error_count +=1
                with open(f'{diretory_out}results/log_error_slither.txt', 'a') as arquivo:
                    arquivo.write(f'Qtd erro {error_count} arquivo falha {file}\n')
                # Você pode adicionar mais linhas conforme necessário
            with open(f'{diretory_out}results/resultado_slither.txt', 'a') as arquivo:
                arquivo.write(f'{str(result)}\n')
        
        #Quantidade de sols gerados
        sol_count = os.listdir(diretory_out+'json/')

        delta_time = time.time() - start_time

        with open(f'{diretory_out}results/log.txt', 'a') as arquivo:
            arquivo.write(f'Quantidade de arquivos{len(files)}\nQuantidade de arquivos que rodaram{sol_count}\nTempo gasto {delta_time}')
       
      
    #Resumir as informações dos json em um arquivo intermediário menor
    def resume_json(self,diretory_in='',diretory_out=''):

        #Criar os diretórios caso não existam e seja necessário
        self.create_directory(diretory_in)
        self.create_directory(diretory_out)

        #Carregando os nomes da pasta
        folder_list = os.listdir(diretory_in)
        print(folder_list)

        #Lista que vai conter os smart contracts levantados
        lista_sol = []
        vulnerabilidades_lista=[]
        solidity_lidos = 0
        solidity_erro = 0
        lista_erro =[]

        #Percorrer os arquivos json
        for arquivo in  folder_list:
            json_arquivo = open(diretory_in+arquivo)
            #print(json_arquivo)
            solidity_lidos+=1

            try:
                sol_json = json.load(json_arquivo)
            except Exception as e:
                solidity_erro+=1
                lista_erro.append(e)
            
            
            #Extraindo os elementos com as vulnerabilidades 
            try:
                #vulnerabilidades_lista = sol_json['results']['detectors'][0]['check']
                vulnerabilidades_lista = sol_json['results']['detectors']
            except Exception as e:

                print('A exceção foi ',e)


            lista_nome_vulnerabilidades =[]
            #Correndo pelas vulnerabilidades previamente carregadas em uma lista
            for vulnerabilidade in vulnerabilidades_lista:
                lista_nome_vulnerabilidades.append(vulnerabilidade['check'])

        #preenchendo a lista com as informações
            lista_sol.append({'nome':arquivo,'vulnerabilidades':lista_nome_vulnerabilidades})
        
        #print(lista_smart_contracts)
        

        with open(f'{diretory_out}data.json', 'w') as json_file:
            json.dump(lista_sol,json_file,indent=4)

        with open(f'{diretory_out}log.txt', 'w') as log:
            log.write(f' Soliditys {solidity_lidos} \n Erros {solidity_erro}\n Lista erros {lista_erro}')

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

        

    def dasp (self, df, arquivo):

        dasp_dic = {'arbitrary-send': 'access_control', 'assembly': 'Ignore', 'calls-loop': 'denial_service', 'constable-states': 'Ignore', 'constant-function': 'Ignore', 'controlled-delegatecall': 'access_control', 'deprecated-standards': 'Ignore', 'erc20-indexed': 'Ignore', 'erc20-interface': 'Ignore', 'external-function': 'Ignore', 'incorrect-equality': 'Other', 'locked-ether': 'Other', 'low-level-calls': 'unchecked_low_calls', 'naming-convention': 'Ignore', 'reentrancy-benign': 'reentrancy', 'reentrancy-eth': 'reentrancy', 'reentrancy-no-eth': 'reentrancy', 'shadowing-abstract': 'Ignore', 'shadowing-builtin': 'Ignore', 'shadowing-local': 'Ignore', 'shadowing-state': 'Ignore', 'solc-version': 'Ignore', 'suicidal': 'access_control', 'timestamp': 'time_manipulation', 'tx-origin': 'access_control', 'uninitialized-local': 'Other', 'uninitialized-state': 'Other', 'uninitialized-storage': 'Other', 'unused-return': 'unchecked_low_calls', 'unused-state': 'Ignore'}

        df_dasp= pd.DataFrame(0, index=range(df.shape[0]),columns=['access_control','arithmetic','denial_service','reentrancy','unchecked_low_calls','bad_randomness','front_running',	'time_manipulation',	'short_addresses',	'Other',	'Ignore'])
        
        df_dasp.reset_index(inplace=True)
        df.reset_index(inplace=True)
        
        print(df_dasp)
        print(df)


        #Colocando os encontros das vulnerabilidade de acordo com a tradução para o DASP
        for column in df.columns:

            try:
                df_dasp[dasp_dic[column]]= df_dasp[dasp_dic[column]] + df[column]
            except Exception as e:
                print(e)    
        

        print(df_dasp)
        print('parei')
        df_dasp.to_excel(f'{arquivo}_dasp.xlsx')

        self.soma_dataframe(df_dasp,f'{arquivo}_dasp')

if '__main__'==__name__:

    version='0.8.0'
    name = 'verified-smart-contracts'
    source_solidity = f'./repositories/{name}/'
    destiny_analysis = f'./slither/{version}_{name}/'
    

    sa = SlitherAnalysis('0.8.23')
    print(os.getcwd())


    print(f'{destiny_analysis}json/')
    print(f'{destiny_analysis}json_analysis/')
    print(f'{destiny_analysis}results/')
    print(f'{destiny_analysis}{version}_slither_{name}')
   



    sa.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

    sa.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

    df = sa.montar_dataframe_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}results/')

    sa.soma_dataframe(df,f'{destiny_analysis}{version}_slither_{name}')

    sa.dasp(df,f'{destiny_analysis}{version}_slither_{name}')