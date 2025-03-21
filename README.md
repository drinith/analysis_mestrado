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

# Anexo

## Anexo I

Neste arquivo, o Slither aponta uma vulnerabilidade existente, mas não especifica o local exato. Na análise do Slither, o arquivo `ether_lotto.sol` é corretamente revisado pelos especialistas, apontando a vulnerabilidade para:

```solidity
// Compute some *almost random* value for selecting winner from current 
// transaction.
// <yes> <report> TIME_MANIPULATION
var random = uint(sha3(block.timestamp)) % 2;













## 📬 Contato

👤 **Felipe Mello Fonseca**  
🎓 Mestrando em Ciência da Computação, CEFET-RJ  
📧 Email: felipe.mello@aluno.cefet-rj.br



