import os
import subprocess
import pandas as pd
import json
import sys
from IPython.display import display
import openpyxl
import time
import re
from smart_tools_analysis.smart_tools_analysis import SmartToolsAnalysis

class SlitherAnalysis(SmartToolsAnalysis):

    def __init__(self, _solc='') -> None:
        super().__init__(_solc)

   
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
                        
            #Checar o pragma e setar a versão mais apropriada
            self.check_pragma(f'{diretory_in}{file}')

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

    def resume_smartbugs_json(self,diretory_in='',diretory_out=''):

        #Criar os diretórios caso não existam e seja necessário
        self.create_directory(diretory_in)
        self.create_directory(diretory_out)

        #Carregando os nomes da pasta
        folder_list = os.listdir(diretory_in)
        

        #Lista que vai conter os smart contracts levantados
        lista_sol = []
        vulnerabilidades_lista=[]
        solidity_lidos = 0
        solidity_erro = 0
        lista_erro =[]

        #Percorrer os arquivos json
        for arquivo in  folder_list:
            json_arquivo = open(f'{diretory_in}/{arquivo}/result.json')
           
            solidity_lidos+=1

            try:
                sol_json = json.load(json_arquivo)
                print(sol_json)
            except Exception as e:
                solidity_erro+=1
                lista_erro.append(e)
            
            
            #Extraindo os elementos com as vulnerabilidades 
            try:
                #vulnerabilidades_lista = sol_json['results']['detectors'][0]['check']
                vulnerabilidades_lista = sol_json['analysis']
            except Exception as e:

                print('A exceção foi ',e)


            lista_nome_vulnerabilidades =[]
            #Correndo pelas vulnerabilidades previamente carregadas em uma lista
            for vulnerabilidade in vulnerabilidades_lista:
                lista_nome_vulnerabilidades.append(vulnerabilidade['check'])

        #preenchendo a lista com as informações
            lista_sol.append({'nome':f'{arquivo}.sol.json','vulnerabilidades':lista_nome_vulnerabilidades})
        
        #print(lista_smart_contracts)
        

        with open(f'{diretory_out}/data.json', 'w') as json_file:
            json.dump(lista_sol,json_file,indent=4)

        with open(f'{diretory_out}/log.txt', 'w') as log:
            log.write(f' Soliditys {solidity_lidos} \n Erros {solidity_erro}\n Lista erros {lista_erro}')

    

        

    def dasp (self, df, arquivo):

        #discionário Dasp criado relacionado com o slither
        dasp_dic = {'arbitrary-send': 'access_control', 'assembly': 'Ignore', 'calls-loop': 'denial_service', 'constable-states': 'Ignore', 'constant-function': 'Ignore', 'controlled-delegatecall': 'access_control', 'deprecated-standards': 'Ignore', 'erc20-indexed': 'Ignore', 'erc20-interface': 'Ignore', 'external-function': 'Ignore', 'incorrect-equality': 'Other', 'locked-ether': 'Other', 'low-level-calls': 'unchecked_low_calls', 'naming-convention': 'Ignore', 'reentrancy-benign': 'reentrancy', 'reentrancy-eth': 'reentrancy', 'reentrancy-no-eth': 'reentrancy', 'shadowing-abstract': 'Ignore', 'shadowing-builtin': 'Ignore', 'shadowing-local': 'Ignore', 'shadowing-state': 'Ignore', 'solc-version': 'Ignore', 'suicidal': 'access_control', 'timestamp': 'time_manipulation', 'tx-origin': 'access_control', 'uninitialized-local': 'Other', 'uninitialized-state': 'Other', 'uninitialized-storage': 'Other', 'unused-return': 'unchecked_low_calls', 'unused-state': 'Ignore'}

        #Criando um dataframe com as colunas do dasp
        df_dasp= pd.DataFrame(0, index=range(df.shape[0]),columns=['access_control','arithmetic','denial_service','reentrancy','unchecked_low_calls','bad_randomness','front_running',	'time_manipulation',	'short_addresses',	'Other',	'Ignore'])
        
        df_dasp.reset_index(inplace=True)
        df.reset_index(inplace=True)
      


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

