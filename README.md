# 📌 Evolução das Ferramentas para Detecção de Vulnerabilidades em Smart Contracts

## 📖 Resumo

Este repositório está relacionado ao projeto de mestrado que investiga a evolução das ferramentas para detecção de vulnerabilidades em contratos inteligentes. O estudo foca na análise das ferramentas **Mythril** e **Slither**, comparando sua eficácia e evolução ao longo do tempo.

## 📝 Sobre o Artigo

O artigo discute a importância da segurança em contratos inteligentes e como ferramentas automatizadas auxiliam na detecção de vulnerabilidades. A pesquisa compara **Mythril** e **Slither**, destacando suas capacidades, limitações e evolução no contexto da auditoria de segurança em blockchain.

## 🔬 Experimento

O experimento consiste na análise de um conjunto de contratos inteligentes utilizando as ferramentas mencionadas. Foram avaliados aspectos como:

- ✅ **Precisão** na identificação de vulnerabilidades
- 🛡️ **Cobertura** de diferentes tipos de falhas
- ⏳ **Tempo de execução** e eficiência das ferramentas

Os resultados obtidos ajudam a entender as vantagens e limitações de cada abordagem, contribuindo para o aprimoramento da segurança em contratos inteligentes.


# 📑 Anexos

# Slither Vulnerability Analysis

# Análise de Vulnerabilidades em Smart Contracts com Slither

Este documento detalha a análise de vulnerabilidades encontradas em smart contracts usando a ferramenta Slither, comparando os resultados com as análises do projeto SmartBugs.

Anexo I: Vulnerabilidade em ether_lotto.sol
O Slither apontou uma vulnerabilidade no arquivo ether_lotto.sol, mas com imprecisão na localização exata. A análise inicial identificou a seguinte linha como vulnerável:

Solidity

// Compute some *almost random* value for selecting winner from current
//transaction.
// <yes> <report> TIME_MANIPULATION
var random = uint(sha3(block.timestamp)) % 2;
Na versão 0.24.7 do Slither, essa linha foi classificada como "weak-prng" no JSON de saída. Para a vulnerabilidade "time_manipulation", o Slither apontou para outra linha:

"description": "EtherLotto.play() (repositories/SmartBugs-curated/ether_lotto.sol#33-57) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- random == 0 (repositories/SmartBugs-curated/ether_lotto.sol#46)\n",

Solidity

if (random == 0)
O Slither errou a localização da vulnerabilidade, pois, embora o problema esteja nos valores de random, a causa raiz é o uso do block.timestamp. O erro não está na verificação do if, como apontado pelo Slither, mas sim na inicialização de random com o timestamp.

Uma versão anterior do Slither, utilizada no projeto SmartBugs, também identificou o erro no if:

"check": "timestamp", "impact": "Low", "confidence": "Medium", "description": "EtherLotto.play (/dataset/time_manipulation/ether_lotto.sol#33-57) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- random == 0 (/dataset/time_manipulation/ether_lotto.sol#46-56)\n",

Anexo II: Análise Detalhada de Vulnerabilidades Time Manipulation
Os seguintes smart contracts foram identificados com vulnerabilidades de Time Manipulation: ether_lotto.sol, governmental_survey.sol, roulette.sol e timed_crowdsale.sol.

ether_lotto.sol
Linha Vulnerável:
Solidity

// <yes> <report> TIME_MANIPULATION
var random = uint(sha3(block.timestamp)) % 2;
Saída do SmartBugs/Slither:
"description": "EtherLotto.play (/dataset/time_manipiation/ether_lotto.sol#33-57) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- random == 0 (/dataset/time_manipulation/ether_lotto.sol#46-56)\n",

O Slither identificou a vulnerabilidade no bloco condicional, não na linha exata onde o timestamp é usado.
governmental_survey.sol
Linha Vulnerável:
Solidity

// <yes> <report> TIME_MANIPULATION
lastInvestmentTimestamp = block.timestamp;
Saída do SmartBugs/Slither:
"description": "Governmental.resetInvestment (/dataset/time_manipulation/governmental_survey.sol#30-40) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- block.timestamp < lastInvestmentTimestamp + ONE_MINUTE (/dataset/time_manipulation/governmental_survey.sol#31-32)\n",

O Slither apontou para a comparação do timestamp, não para a atribuição inicial.
roulette.sol
Linhas Vulneráveis:
Solidity

require(now != pastBlockTime); // only 1 transaction per block
pastBlockTime = now;
Saída do SmartBugs/Slither:
Nenhuma vulnerabilidade de Time Manipulation detectada.
timed_crowdsale.sol
Linha Vulnerável:
Solidity

// <yes> <report> TIME_MANIPULATION
return block.timestamp >= 1546300800;
Saída do SmartBugs/Slither:
"description": "TimedCrowdsale.isSaleFinished (/dataset/time_manipulation/timed_crowdsale.sol#11-14) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- block.timestamp >= 1546300800 (/dataset/time_manipulation/timed_crowdsale.sol#13)\n",

O Slither identificou a vulnerabilidade corretamente.
Observação: A contagem de vulnerabilidades de Time Manipulation relatada pode estar incorreta, pois a análise manual identificou discrepâncias.

Anexo III: Vulnerabilidades em FibonacciBalance.sol
O arquivo FibonacciBalance.sol possui duas vulnerabilidades de controle de acesso:

Solidity

// <yes> <report> ACCESS_CONTROL
require(fibonacciLibrary.delegatecall(fibSig, withdrawalCounter));
msg.sender.transfer(calculatedFibNumber * 1 ether);
Solidity

function() public {
// <yes> <report> ACCESS_CONTROL
require(fibonacciLibrary.delegatecall(msg.data));
}
A saída do SmartBugs/Slither para a segunda vulnerabilidade é:

"address": 212, "code": "fibonacciLibrary.delegatecall(msg.data)", "debug": "", "description": "Be aware that the called contract gets unrestricted access to this contract's state.", "filename": "/dataset/unchecked_low_level_calls/FibonacciBalance.sol", "function": "fallback", "lineno": 38, "title": "DELEGATECALL to a user-supplied address", "type": "Informational",

Acredita-se que a contagem de vulnerabilidades tenha sido inflada devido à detecção da mesma vulnerabilidade em duas linhas diferentes.





## 📬 Contato

👤 **Felipe Mello Fonseca**  
🎓 Mestrando em Ciência da Computação, CEFET-RJ  
📧 Email: felipe.mello@aluno.cefet-rj.br



