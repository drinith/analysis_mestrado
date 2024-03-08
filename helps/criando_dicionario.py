import csv

# Lista para armazenar os dados do CSV
matriz = []

# Abrir o arquivo CSV e ler os dados
#with open('./helps/vulnerabilities_mapping_mythril.csv', newline='') as csvfile:
with open('./helps/vulnerabilities_.csv', newline='') as csvfile:
    # Criar um leitor CSV
    csvreader = csv.reader(csvfile)
    
    # Iterar sobre cada linha no arquivo CSV
    for linha in csvreader:
        # Adicionar cada linha à matriz
        matriz.append(linha)

head = matriz.pop(0)
dicionario ={}
# Exibir a matriz resultante
for linha in matriz:
    
    for pos in range(len(linha)-1):
    
        if(linha[pos+1]=='TRUE'):
            dicionario[linha[0]]=head[pos+1]

print(dicionario)



