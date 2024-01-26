import re

class SmartToolsAnalysis():
    
    solc =''
    solc_dic = {'4':'0.4.26','5':'0.5.17','6':'0.6.12','7':'0.7.6','8':'0.8.23'}
    solc_numero ='' 

    def __init__(self,_solc='') -> None:

        self.set_solc(_solc)
        self.solc = _solc
        self.solc_numero = _solc.split('.')[1]

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
