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

## 📌 Anexo I: Análise do Slither

O Slither identificou uma vulnerabilidade no arquivo `ether_lotto.sol`, mas errou na localização exata. A ferramenta apontou a seguinte linha como vulnerável:

```solidity
// Compute some *almost random* value for selecting winner from current transaction.
// <yes> <report> TIME_MANIPULATION
var random = uint(sha3(block.timestamp)) % 2;
```

Porém, na versão 0.24.7, o Slither classificou essa vulnerabilidade como `weak-prng`. Para `time_manipulation`, a ferramenta apontou outra linha:

```solidity
if (random == 0)
```

Isso indica que o Slither não identificou corretamente a raiz da vulnerabilidade, que está no uso do `block.timestamp`.

## 📌 Anexo II: Vulnerabilidades Detectadas

Os contratos auditados que apresentaram vulnerabilidade em **Time Manipulation** foram:

- `ether_lotto.sol`
- `governmental_survey.sol`
- `roulette.sol`
- `timed_crowdsale.sol`

A seguir, exemplos das vulnerabilidades encontradas:

### `ether_lotto.sol`
```solidity
// <yes> <report> TIME_MANIPULATION
var random = uint(sha3(block.timestamp)) % 2;
```

### `governmental_survey.sol`
```solidity
// <yes> <report> TIME_MANIPULATION
lastInvestmentTimestamp = block.timestamp;
```

### `roulette.sol`
```solidity
// <yes> <report> TIME_MANIPULATION
require(now != pastBlockTime);
pastBlockTime = now;
```

### `timed_crowdsale.sol`
```solidity
// <yes> <report> TIME_MANIPULATION
return block.timestamp >= 1546300800;
```

O Slither conseguiu detectar corretamente a vulnerabilidade em `timed_crowdsale.sol`, mas falhou em algumas outras análises.

## 📌 Anexo III: Análise do FibonacciBalance.sol

O arquivo `FibonacciBalance.sol` apresentou duas vulnerabilidades **Access Control**:

```solidity
// <yes> <report> ACCESS_CONTROL
require(fibonacciLibrary.delegatecall(fibSig, withdrawalCounter));
msg.sender.transfer(calculatedFibNumber * 1 ether);
```

```solidity
// <yes> <report> ACCESS_CONTROL
require(fibonacciLibrary.delegatecall(msg.data));
```

A análise do SmartBugs confirmou que o problema está no uso de `delegatecall`, concedendo acesso irrestrito ao contrato externo.

---

Este repositório documenta as vulnerabilidades analisadas e comparações feitas entre as versões do Slither. 📊🔍





## 📬 Contato

👤 **Felipe Mello Fonseca**  
🎓 Mestrando em Ciência da Computação, CEFET-RJ  
📧 Email: [seu email]



