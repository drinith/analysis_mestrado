import os

def listar_arquivos_e_subpastas(diretorio):
  """
  Função que lista os nomes das subpastas e dos arquivos dentro de um diretório.

  Argumentos:
    diretorio: Caminho para o diretório que deseja listar.

  Retorno:
    Uma lista com os nomes das subpastas e dos arquivos.
  """

  # Lista os arquivos e subpastas no diretório
  itens = os.listdir(diretorio)

  # Cria uma lista para armazenar os nomes
  nomes = []

  # Itera sobre cada item na lista
  for item in itens:
    # Verifica se o item é uma subpasta
    if os.path.isdir(os.path.join(diretorio, item)):
      # Adiciona o nome da subpasta à lista
      nomes.append(f"{item} (subpasta)")
    else:
      # Adiciona o nome do arquivo à lista
      nomes.append(item)

  # Retorna a lista com os nomes
  return nomes


# Caminho do diretório que deseja listar
diretorio = "../repositories/dataset"

# Lista os nomes das subpastas e dos arquivos
nomes = listar_arquivos_e_subpastas(diretorio)

# Imprime os nomes
for nome in nomes:
  print(nome)
