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

## Anexo I

# Anexo I

Neste arquivo, o Slither aponta uma vulnerabilidade existente, mas não acerta especificamente o local. Na análise do Slither, o arquivo `ether_lotto.sol` é analisado pelos especialistas, apontando a vulnerabilidade para:

```solidity
// Compute some *almost random* value for selecting winner from current transaction.
// <yes> <report> TIME_MANIPULATION
var random = uint(sha3(block.timestamp)) % 2;
```

Na análise do Slither 0.24.7, essa linha contém uma vulnerabilidade, mas é classificada no JSON como "check": "weak-prng". Para time_manipulation, a análise aponta para outra linha que não foi a levantada:

"description": "EtherLotto.play() (repositories/SmartBugs-curated/ether_lotto.sol#33-57) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- random == 0 (repositories/SmartBugs-curated/ether_lotto.sol#46)\n",

O Slither erra o local da vulnerabilidade, pois, apesar da vulnerabilidade estar nos valores contidos no random devido ao uso do timestamp, o problema não está na verificação do if como o Slither apontou. A vulnerabilidade está no fato do sorteio usar o timestamp, o que inicia a vulnerabilidade.

A versão anterior do Slither, na análise do trabalho do SmartBugs, encontrou o erro no mesmo lugar, no if.
A versão anterior do Slither identificou o mesmo erro no mesmo local, no if:

"check": "timestamp",
"impact": "Low",
"confidence": "Medium",
"description": "EtherLotto.play (/dataset/time_manipulation/ether_lotto.sol#33-57) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- random == 0 (/dataset/time_manipulation/ether_lotto.sol#46-56)\n",

## Anexo II
Dentre os smart contracts analisados que apresentam vulnerabilidade em Time Manipulation, estão: ether_lotto.sol, governmental_survey.sol, roulette.sol e timed_crowdsale.sol. Dentro do código do ether_lotto.sol, encontramos a vulnerabilidade apontada na linha 43.

// <yes> <report> TIME_MANIPULATION
var random = uint(sha3(block.timestamp)) % 2;

Buscando a vulnerabilidade na análise do trabalho do SmartBugs na ferramenta Slither, encontramos:

"description": "EtherLotto.play (/dataset/time_manipulation/ether_lotto.sol#33-57) uses timestamp for comparisons\n\tDangerous comparisons:\n\t- random == 0 (/dataset/time_manipulation/ether_lotto.sol#46-56)\n",

Este trecho mostra a saída da única vulnerabilidade relacionada ao Time Manipulation. A vulnerabilidade foi detectada pela ferramenta no bloco condicional, como podemos ver a seguir. Assim, podemos notar que não foi exatamente onde o código foi analisado.

```solidity
// Distribution: 50% of participants will be winners.
if (random == 0) {
    // Send fee to bank account.
    bank.transfer(FEE_AMOUNT);

    // Send jackpot to winner.
    msg.sender.transfer(pot - FEE_AMOUNT);

    // Restart jackpot.
    pot = 0;
}

```
O arquivo governmental_survey.sol possui a vulnerabilidade apontada para a linha 27, como:

```solidity
// <yes> <report> TIME_MANIPULATION
lastInvestmentTimestamp = block.timestamp;
```





## 📬 Contato

👤 **Felipe Mello Fonseca**  
🎓 Mestrando em Ciência da Computação, CEFET-RJ  
📧 Email: felipe.mello@aluno.cefet-rj.br



