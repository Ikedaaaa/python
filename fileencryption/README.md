# fileencryption
Projeto desenvolvido para criptografar arquivos usando senha

## Necessidade
Gostaria de ter alguns arquivos criptografados mas não queria baixar uma aplicação.
Acredito que desenvolver algo por conta própria poderia ser mais seguro, sabendo como o programa foi desenvolvido.
Também seria bom aproveitar a oportunidade para praticar desenvolvimento em python

## Funcionamento
A intenção é que, ao rodar o script, sejam apresentadas três opções:
 - Definir/Redefinir senha para criptografia;
 - Criptografar/Descriptografar algum arquivo;
 - (Talvez, se for possível ou viável) Descriptografar um arquivo, abrir ele (launch application), e quando fechar, ou quando rodar comando para fechar (talvez), criptografar novamente;

Será usada a criptografia simétrica, ou seja, a mesma chave usada para criptografar o conteúdo, será usada para descriptografar.

A biblioteca importada usa o algoritmo AES 

## 1. Definir/Redefinir senha para criptografia
 - Se não tiver senha definida, pede input da senha e confirmação da senha (digitar a senha duas vezes e comparar como é feito em diversos formulários de sign in), e escreve o hash dela em um arquivo de texto.
 - Se tiver, pede a senha antiga, verifica no arquivo de texto o hash da senha e então chama a função de definição de nova senha.

### Algoritmo de hash
Por questões de segurança, o algoritmo de hash usado será o Bcrypt, para que seja possível definir o Work Factor, seja usado um Salt e aumente muito a dificuldade de quebrar a senha

## 2. Criptografar/Descriptografar algum arquivo
Inputs:
 - O caminho do arquivo, com ele incluso (e.g.: C:\Users\<user>\Desktop\test.txt);
 - A senha.
Se não tiver descriptografado, criptografa e vice-versa;

Ao digitar a senha, será gerado o hash usando o Bcrypt e comparado com o conteúdo do arquivo de senha.

Caso a senha esteja correta, ela será usada para gerar a chave de criptografia

## 3. Descriptografar, abrir, fechar e criptografar novamente;
Recebe os mesmos parâmetros do tópico 2, mas após descriptografar, abre o arquivo e, quando fechar (ou talvez, quando rodar comando para fechar ou ambos), criptografa o arquivo novamente, automaticamente.

## Estrutura de arquivos
 - Arquivo com hash da senha
 - Arquivo com o Salt gerado ao definir a senha

## Usos Externos
 - Cryptography library (https://pypi.org/project/cryptography/)
   - From cryptography, it's going to be used Fernet and Scrypt
 - Bcrypt module (https://pypi.org/project/bcrypt/)

## Sources
 - https://www.thepythoncode.com/article/encrypt-decrypt-files-symmetric-python
 - https://www.geeksforgeeks.org/hashing-passwords-in-python-with-bcrypt/