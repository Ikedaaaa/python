# disponibilidadelivro
Projeto desenvolvido para automatizar a tarefa de verificar a disponibilidade do livro Criptomoedas: Melhor que Dinheiro

## Necessidade
Gostaria de comprar o livro mas na página sempre era apresentada a mensagem de que não está disponível. Ao entrar em contato com o suporte disseram que não havia previsão para o livro voltar a ficar disponível.
Como não há uma forma de solicitar para que seja enviado um e-mail quando houver disponibilidade, decidi criar algo que automatizasse isso.

## Descobrindo a disponibilidade
Para verificar a disponibilidade, era necessário sempre abrir a URL
 - https://www.empiricus.com.br/livros/
Para depois abrir a URL do Livro
 - https://store.empiricus.com.br/livro-criptomoedas-avulso/
Que mostrava uma mensagem de "Código 1000: Verificamos que esta oferta não está disponível no momento."

Investiguei as requisições que eram feitas ao acessar essa página e identifiquei que a requisição que trazia as informações em JSON era feita usando método POST para a URL
 - https://store-api.empiricus.com.br/commerce/v1/storefront/livro-criptomoedas-avulso

A requisição tinha o corpo em JSON:
 - {"payment_method": "creditCard"}

No meio da resposta da requisição, além de informações como título do livro, preço, métodos de pagamento, também há a informação da disponibilidade:
"availability": {
    "available": false,
    "redirect_slug": "",
    "redirect_url": "",
    "error_code": 1000
},

## Notificação
Para avisar quando o livro está disponível de maneira automática, foram pensadas duas possibilidades:

### Deixar script rodando
 - Seria necessário criar um tread para executar a parte da requisição periodicamente, a cada 24h ou mais, talvez.
 - A cada requisição, se retornasse "false" pra disponibilidade, seria feito apenas um log, para identificar que foi feita a requisição pelo menos (arquivo disponibilidadelivro.log)
 - A necessidade do log serviria também para identificar caso algo desse errado na requisição, como uma possível mudança na URL
 - Quando a disponibilidade se tornasse "true", seria chamado um sistema de notificação, como se fosse o email automático avisando que o livro voltou a ficar disponível

### Execução automática na inicialização do computador
 - A cada inicialização seria feita a requisição
 - Caso não estivesse disponível, seria feito um log também (arquivo disponibilidadelivro.log)
 - Quando se tornasse disponível, seria criado apenas um txt em um local especificado, avisando que se tornou disponível

#### Requisitos
Para que o script gere um arquivo informando que o livro se tornou disponível, será necessário criar na própria pasta do arquivo disponibilidadelivro.py
 - Um arquivo txt com nome *bookavailablefiledirectory.txt*

O conteúdo deve ser apenas o local para ser gerado o arquivo alertando a disponibilidade do livro. **O nome do arquivo deve estar incluso**.
Exemplos:
 - C:\Users\user\Desktop\LIVRODISPONIVEL.TXT
 - C:\Users\user\Downloads\the_book_is_available.txt