import re
import subprocess
import os
import json
import pandas as pd
from IPython.display import display, HTML

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

    def criar_diretorio(self,_diretorio):

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
        self.criar_diretorio(diretory_in)
        self.criar_diretorio(diretory_out)
        
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

        # Criar um DataFrame do pandas a partir do dicionário , Esse Dataframe é composto pelas vulnerabilidades padrão da ferramenta
        #Esse dataframe mostra o encontro com as repetições de um vulnerabilidade no solidity    
        df = pd.DataFrame(contagem_vulnerabilidades).fillna(0).astype(int)
        display(df)
        dt =df.transpose()

        #Cria uma planilha que ficará dentro do diretório results
        dt.to_excel(f'{diretory_out}resultado.xlsx')
        
        return df.transpose()
    
 

    def soma_dataframe(self,df,arquivo):

        # Criar um novo DataFrame com a soma total de cada vulnerabilidade

        #Pegando o dataframe somando as linhas que vai virar uma série e para tranformar em um "dataframe" foi resetado o index
        soma_total_vulnerabilidades = df.sum(axis=0).reset_index()
        
        #Criando os cabeçalhos novos 
        soma_total_vulnerabilidades.columns = ['Vulnerabilidade', 'Soma_Total']

        # Ordenar o DataFrame pela coluna 'Soma_Total' em ordem decrescente
        soma_total_vulnerabilidades = soma_total_vulnerabilidades.sort_values(by='Soma_Total', ascending=False)

        # Visualizar o DataFrame resultante
        soma_total_vulnerabilidades.to_excel(f'{arquivo}_soma.xlsx')

    def transforma_dasp(self,dicionario:dict,df:pd.DataFrame, arquivo=''):
        
        #discionário Dasp criado relacionado com o slither
        dasp_dic = dicionario

        #Criando um dataframe com as colunas que serão as vulnerabilidades do dasp
        df_dasp= pd.DataFrame(0,index=df.index, columns=['access_control','arithmetic','denial_service','reentrancy','unchecked_low_calls','bad_randomness','front_running',	'time_manipulation',	'short_addresses',	'Other',	'Ignore'])
        
        display(df_dasp)  


        #Colocando os encontros das vulnerabilidade de acordo com a tradução para o DASP
        for column in df.columns:

            try:
                df_dasp[dasp_dic[column]]= df_dasp[dasp_dic[column]] + df[column]
            except Exception as e:
                print(e)    
        

        print(df_dasp)
        print('parei')
        df_dasp.to_excel(f'{arquivo}_dasp.xlsx')

        #Futuro acho melhor tirar daqui
        self.soma_dataframe(df_dasp,f'{arquivo}_dasp')

        return  df_dasp 



    def acurar (self, resultado:pd.DataFrame, gabarito:pd.DataFrame):
        
        
        #carregar resultado
        #carregar gabarito
        gabarito.index = gabarito.iloc[:,0]
        gabarito= gabarito.drop(gabarito.columns[0],axis=1)
        gabarito= gabarito.drop('Unnamed: 0')
        print(gabarito)
        df_acurado = resultado.copy()

        df_acurado.loc[:,:]=''
        #comparar e criar uma lista onde cada solidity é classificado com lista vulnerabilidades encontradas , a que deveria ter , VP, VN, FP , FN
        #Fazer de forma manual pro enquanto caminhar pelo dataframe de resultado e ver o gabarito

        for index in resultado.index:

            for coluna in resultado.columns:

                #Teste onde teve presença de vulnerabilidade e o gabarito confirma
                if(resultado.loc[index,coluna]>=1 and gabarito.loc[index,coluna]>=1):
                    df_acurado.loc[index,coluna]='VP'
                if(resultado.loc[index,coluna]==0 and gabarito.loc[index,coluna]>=1):
                    df_acurado.loc[index,coluna]='FN'
                if(resultado.loc[index,coluna]>=1 and gabarito.loc[index,coluna]==0):
                    df_acurado.loc[index,coluna]='FP'
        

        print(df_acurado)