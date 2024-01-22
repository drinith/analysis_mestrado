import re

expressao_regular = r'pragma solidity\s*\^\s*\d\.(\d)'
#expressao_regular = r"\d{1}"

resultado = re.search(expressao_regular, '@openzeppelin/contracts/utils/Context.sol\n\npragma solidity ^0.8.0;\n\n/*\n')

if resultado:
    numero_entre_pontos = resultado.group(1)
    print(f'Número entre os pontos: {numero_entre_pontos}')
else:
    print('Padrão não encontrado.')

print('Fim')