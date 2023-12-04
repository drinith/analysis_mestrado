import pandas as pd
import matplotlib.pyplot as plt
import os
import json
import sys



path ='./verified-smart-contracts-json'


dir_path = os.path.dirname(os.path.realpath(sys.argv[0]))

print(dir_path)

class Sol:

    _nome=''
    _vulnerabilidades=[]


    def __init__(self,nome):

        self._nome = nome
        self._vulnerabilidades=[]


def montar_dataframe_todo_erro() -> pd.DataFrame:

    #Carregando os nomes da pasta
    folder_list = os.listdir(path)
    #print(folder_list)

    #Lista que vai conter os smart contracts levantados
    lista_sol = []
    vulnerabilidades_lista=[]
    for arquivo in  folder_list:
        json_arquivo = open(path+'/'+arquivo)
        #print(json_arquivo)
        
        try:
            sol_json = json.load(json_arquivo)
        except Exception as e:
            print(e)

        #Instanciando smart contracts com o nome levantado do json
        sol = Sol(arquivo)

        try:
            #vulnerabilidades_lista = sol_json['results']['detectors'][0]['check']
            vulnerabilidades_lista = sol_json['results']['detectors']
        except Exception as e:

            print('A exceção foi ',e)


        for vulnerabilidade in vulnerabilidades_lista:
            sol._vulnerabilidades.append(vulnerabilidade['check'])

    #preenchendo a lista com as informações
        lista_sol.append(sol)
    
    #print(lista_smart_contracts)

    with open('data.json', 'w') as json_file:
        json.dump(lista_sol, json_file)

    print(lista_sol)
    df = pd.DataFrame(columns=lista_sol)

    #df = pd.DataFrame(columns=[scs._vulnerabilidades for scs in lista_smart_contracts])
    df = pd.DataFrame()
    df['name']=1

    #Tentando criar as colunas com os nomes das vulnerabililidades
    for scs in lista_sol:

        df[scs._vulnerabilidades]=1

    index=0
    df = pd.DataFrame([[0]* len(df.columns)]*len(lista_sol),columns=df.columns)

    for scs in lista_sol:


        df.loc[index,'name']=scs._nome

    for coluna in scs._vulnerabilidades:

      df.loc[index,coluna]+=1
    index+=1

    return df


if '__main__'==__name__:

    df = montar_dataframe_todo_erro()