import os
import pandas as pd 

def buscar_arquivos(diretorio=''):
  """
  Função que busca todos os arquivos em um diretório e suas subpastas.

  Args:
    diretorio: O diretório onde a busca deve ser iniciada.

  Returns:
    Uma lista com os nomes de todos os arquivos encontrados.
  """

  arquivos = []
  for pasta, subpastas, arquivos_na_pasta in os.walk(diretorio):
    arquivos.extend([os.path.join(pasta, arquivo) for arquivo in arquivos_na_pasta])
  

  lista=[]

  for arquivo in arquivos:

    # Separando a string por partes
    partes = os.path.split(arquivo)

    # Criando a lista com as informações desejadas
    lista.append([partes[0].split("/")[-1], partes[1]])
    

  pd.DataFrame(data=lista,columns=['vulnerabilidade','solidity']).to_excel(f'gabarito_{diretorio.split("/")[-1]}.xlsx')



# Exemplo de uso
diretorio_raiz = "./repositories/dataset"

arquivos_encontrados = buscar_arquivos(diretorio_raiz)

print('fim')

#print(f"Arquivos encontrados: {arquivos_encontrados}")