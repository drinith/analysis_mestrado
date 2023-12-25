import pandas as pd
import os
import json
import sys
from IPython.display import display
import openpyxl

path ='./verified-smart-contracts-json'

dir_path = os.path.dirname(os.path.realpath(sys.argv[0]))

print(dir_path)

def run_slither_solidity():

    #Carregando os nomes da pasta
    folder_list = os.listdir(path)
    print(folder_list)

    #Lista que vai conter os smart contracts levantados
    lista_sol = []
    vulnerabilidades_lista=[]
    lista_contratos = []
    solidity_lidos = 0
    solidity_erro = 0
    lista_erro =[]


    for arquivo in  folder_list:
        json_arquivo = open(path+'/'+arquivo)
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
        #Correndo pelas 
        for vulnerabilidade in vulnerabilidades_lista:
            lista_nome_vulnerabilidades.append(vulnerabilidade['check'])

    #preenchendo a lista com as informações
        lista_sol.append({'nome':arquivo,'vulnerabilidades':lista_nome_vulnerabilidades})
    
    #print(lista_smart_contracts)
    

    with open('data.json', 'w') as json_file:
        json.dump(lista_sol,json_file,indent=4)

    with open('log.txt', 'w') as log:
        log.write(f' Soliditys {solidity_lidos} \n Erros {solidity_erro}\n Lista erros {lista_erro}')

def montar_dataframe_json():
    
    json_file = open('./data.json')
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
    dt.to_excel('resultado.xlsx')
    return df.transpose()



def montar_dataframe_todo_erro() -> pd.DataFrame:

    run_slither_solidity()    
    
def soma_dataframe(df):

    # Criar um novo DataFrame com a soma total de cada vulnerabilidade
    soma_total_vulnerabilidades = df.sum(axis=0).reset_index()
    soma_total_vulnerabilidades.columns = ['Vulnerabilidade', 'Soma_Total']

    # Ordenar o DataFrame pela coluna 'Soma_Total' em ordem decrescente
    soma_total_vulnerabilidades = soma_total_vulnerabilidades.sort_values(by='Soma_Total', ascending=False)

    # Visualizar o DataFrame resultante
    soma_total_vulnerabilidades.to_excel('soma.xlsx')   


if '__main__'==__name__:

    run_slither_solidity()
    df=montar_dataframe_json()
    soma_dataframe(df)
  

    # df = montar_dataframe_json()
    # display(df)

    # # Criar um novo DataFrame com a soma total de cada vulnerabilidade
    # soma_total_vulnerabilidades = df.sum(axis=0).reset_index()
    # soma_total_vulnerabilidades.columns = ['Vulnerabilidade', 'Soma_Total']

    # # Ordenar o DataFrame pela coluna 'Soma_Total' em ordem decrescente
    # soma_total_vulnerabilidades = soma_total_vulnerabilidades.sort_values(by='Soma_Total', ascending=False)

    # # Visualizar o DataFrame resultante
    # print(soma_total_vulnerabilidades)