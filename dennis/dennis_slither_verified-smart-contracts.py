import pandas as pd
import matplotlib.pyplot as plt
import os
import json
import sys
from IPython.display import display

path ='./verified-smart-contracts-json'

dir_path = os.path.dirname(os.path.realpath(sys.argv[0]))

print(dir_path)

def montar_dataframe_todo_erro() -> pd.DataFrame:

    # #Carregando os nomes da pasta
    # folder_list = os.listdir(path)
    # print(folder_list)

    # #Lista que vai conter os smart contracts levantados
    # lista_sol = []
    # vulnerabilidades_lista=[]
    # for arquivo in  folder_list:
    #     json_arquivo = open(path+'/'+arquivo)
    #     #print(json_arquivo)
        
    #     try:
    #         sol_json = json.load(json_arquivo)
    #     except Exception as e:
    #         print(e)

    #     #Instanciando smart contracts com o nome levantado do json
        

    #     try:
    #         #vulnerabilidades_lista = sol_json['results']['detectors'][0]['check']
    #         vulnerabilidades_lista = sol_json['results']['detectors']
    #     except Exception as e:

    #         print('A exceção foi ',e)

    #     lista_nome_vulnerabilidades =[]
    #     for vulnerabilidade in vulnerabilidades_lista:
    #         lista_nome_vulnerabilidades.append(vulnerabilidade['check'])

    # #preenchendo a lista com as informações
    #     lista_sol.append({'nome':arquivo,'vulnerabilidades':lista_nome_vulnerabilidades})
    
    # #print(lista_smart_contracts)
    

    # with open('data.json', 'w') as json_file:
    #     json.dump(lista_sol,json_file,indent=4)
    
    
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
    print(df)
    
    # df = pd.DataFrame(columns=lista_sol)
    
    # #df = pd.DataFrame(columns=[scs._vulnerabilidades for scs in lista_smart_contracts])
    # df = pd.DataFrame()
    # df['name']=1

    # #Tentando criar as colunas com os nomes das vulnerabililidades
    # for item in lista_sol:

    #     df[item['vulnerabilidades']]=1

    # index=0
    # df = pd.DataFrame([[0]* len(df.columns)]*len(lista_sol),columns=df.columns)
    
    # for item in lista_sol:


    #     df.loc[index,'name']=item['nome']
    #     index+=1
  

    #     for vulnerabilidade in item['vulnerabilidades']:

    #         df.loc[index,vulnerabilidade]+=1
    #     index+=1
    display(df)
    return df


if '__main__'==__name__:

    df = montar_dataframe_todo_erro()
    display(df)