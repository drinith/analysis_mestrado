import os
import subprocess
import pandas as pd
import json
import sys
from IPython.display import display
import openpyxl


class MythrilAnalysis:

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
            #Montar comando do mythril
            # command_mythril = [
            #     'myth',
            #     ' analyze ',
            #     f'{diretory_in}AAC.sol',
            #     '--execution-timeout 4'
            # ]
            #Resultado do comando slither
            #result= subprocess.run(command_mythril, capture_output=True, text=True)
            #result= subprocess.check_output(f'myth analyze {diretory_in}{file}  --execution-timeout 4', shell=True, stderr=subprocess.STDOUT)
            #result= subprocess.run(f'myth analyze {diretory_in}{file} -o jsonv2 --execution-timeout 10', capture_output=True, text=True,shell=True)
            result= subprocess.run(f'myth analyze {diretory_in}{file} -o jsonv2 --max-depth 10', capture_output=True, text=True,shell=True)
            
            print(result.stdout)
            
            #Salvando o resultado do json
            with open(f'{diretory_out}json/{file}.json', 'w') as arquivo:
                    arquivo.write(result.stdout)

            #Verificando se o comando falhou
            if ('warnings/errors' in str(result)):
                error_count +=1
                with open(f'{diretory_out}results/log_error_mythril.txt', 'a') as arquivo:
                    arquivo.write(f'Qtd erro {error_count} arquivo falha {file}\n')
                # Você pode adicionar mais linhas conforme necessário
            with open(f'{diretory_out}results/resultado_mythril.txt', 'a') as arquivo:
                arquivo.write(f'{str(result)}\n')
        
        #Quantidade de sols gerados
        sol_count = os.listdir(diretory_out+'json/')

        with open(f'{diretory_out}results/log.txt', 'a') as arquivo:
            arquivo.write(f'Quantidade de arquivos{len(files)}\nQuantidade de arquivos que rodaram{sol_count}')
      
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
                #vulnerabilidades_lista = sol_json['results']['detectors']
                vulnerabilidades_lista = sol_json[0]['issues']
                #testar lista se está vazia pra chegar a saber se o valor está sendo encontrado em algum momento
                
            except Exception as e:

                print('A exceção foi ',e)

            #Fazendo o teste para ver se o json possui uma vulnerabilidade
            if(vulnerabilidades_lista):
                print("encontrou falha")
                print(vulnerabilidades_lista)
                lista_nome_vulnerabilidades =[]
                #Correndo pelas vulnerabilidades previamente carregadas em uma lista
                for vulnerabilidade in vulnerabilidades_lista:
                    lista_nome_vulnerabilidades.append(vulnerabilidade['swcTitle'])

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
        
    def soma_dataframe(self,df):

        # Criar um novo DataFrame com a soma total de cada vulnerabilidade
        soma_total_vulnerabilidades = df.sum(axis=0).reset_index()
        soma_total_vulnerabilidades.columns = ['Vulnerabilidade', 'Soma_Total']

        # Ordenar o DataFrame pela coluna 'Soma_Total' em ordem decrescente
        soma_total_vulnerabilidades = soma_total_vulnerabilidades.sort_values(by='Soma_Total', ascending=False)

        # Visualizar o DataFrame resultante
        soma_total_vulnerabilidades.to_excel('soma.xlsx')  

if '__main__'==__name__:

    source_solidity = './smartbugs-curated'
    destiny_analysis = './mythril/smartbugs-curated/'

    sa = MythrilAnalysis()
    print(os.getcwd())
    # sa.run_analysis_diretory(diretory_in=source_solidity,diretory_out=destiny_analysis)

    sa.resume_json(f'{destiny_analysis}json/',f'{destiny_analysis}json_analysis/')

    df = sa.montar_dataframe_json(f'{destiny_analysis}json_analysis/',f'{destiny_analysis}json_analysis/')

    sa.soma_dataframe(df)

    

