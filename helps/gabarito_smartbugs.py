import os
import pandas as pd 
from IPython.display import display, HTML

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

    
    #limpar arquivos que podem vir juntos 
    if (partes[1].endswith(".sol")):
      # Criando a lista com as informações desejadas
      lista.append([partes[0].split("/")[-1], partes[1]+'.json'])
      
    
  
  
  #Pegando a lista dos nomes dos arquivos solidity que serão usados como index do dataframe
  arquivos_solidity = [item[1] for item in lista]
  arquivos_solidity.sort()
  
  #pd.DataFrame(data=lista,columns=['vulnerabilidade','solidity']).to_excel(f'gabarito_{diretorio.split("/")[-1]}.xlsx')
    
  df_dasp= pd.DataFrame(0,index=arquivos_solidity, 
                        columns=['access_control','arithmetic','denial_service','reentrancy','unchecked_low_calls','bad_randomness',
                                 'front_running','time_manipulation','short_addresses','Other','Ignore'])

  for elemento in lista:
    df_dasp.loc[elemento[1],elemento[0]]=1

  df_dasp.to_excel(f'gabarito_{diretorio.split("/")[-1]}.xlsx')
    
  print('teste')

if __name__=='__main__':
  # Exemplo de uso
  diretorio_raiz = "./repositories/dataset"

  arquivos_encontrados = buscar_arquivos(diretorio_raiz)

  print('fim')

  #print(f"Arquivos encontrados: {arquivos_encontrados}")