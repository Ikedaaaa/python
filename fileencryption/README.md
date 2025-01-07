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
 - Descriptografar um arquivo, abrir ele (launch application), e quando fechar, criptografar novamente;

Será usada a criptografia simétrica, ou seja, a mesma chave usada para criptografar o conteúdo, será usada para descriptografar.

A biblioteca importada usa o algoritmo AES 

## 1. Definir/Redefinir senha para criptografia
 - Se não tiver senha definida, pede input da senha e confirmação da senha (digitar a senha duas vezes e comparar como é feito em diversos formulários de sign in), e escreve o hash dela em um arquivo de texto.
 - Se tiver, pede a senha antiga, verifica no arquivo de texto o hash da senha e então chama a função de definição de nova senha.

### Algoritmo de hash
Por questões de segurança, o algoritmo de hash usado será o Bcrypt, para que seja possível definir o Work Factor, seja usado um Salt e aumente muito a dificuldade de quebrar a senha

### Input de senha - getpass
Os inputs de senha serão feitos através do módulo getpass.

Com isso, qualquer texto digitado pelo usuário em um input de senha não será refletido no terminal, não revelando a senha digitada.
Pode parecer confuso, como se o teclado não estivesse funcionando, ou como se estivesse travado, porém o texto está sendo captado, só não está sendo mostrado de volta.

### Controle de arquivos criptografados ao redefinir senha
Haverá um arquivo controlando a quantidade de arquivos criptografados.

Isso será feito para impedir que a senha seja trocada caso haja arquivos criptografados.
Pois a chave usada na criptografia do arquivo deve ser a mesma na hora de descriptografar.
Caso o número presente no arquivo de controle seja > 0, será mostrada uma mensagem indicando que todos os arquivos criptografados devem ser descriptografados antes de redefinir a senha.

Caso o arquivo de senha seja apagado para definir uma senha, mas o número presente no arquivo de controle seja > 0, o usuário deverá definir a mesma senha que foi usada anteriormente na criptografia.

 - Caso um arquivo seja criptografado usando uma senha para gerar uma determinada chave, se essa mesma chave não for gerada usando a senha anterior, não será possível descriptografar o arquivo, portanto o conteúdo corre o risco de ser perdido.

O arquivo guardará apenas a quantidade, ao invés de armazenar exatamente quais arquivos foram criptografados.
Pois assim, não serão identificados os arquivos que podem possuir dados sensíveis, o que os levou a serem criptografados.

## 2. Criptografar/Descriptografar algum arquivo
Inputs:
 - O caminho do arquivo, com ele incluso (e.g.: C:/Users/<user>/Desktop/test.txt);
  - Caso queira inserir vários arquivos, basta digitar "1" quando a mensagem de múltiplos arquivos for apresentada, então, inserir em cada linha o arquivo no formato acima;
 - A senha (usando getpass).

Se não tiver descriptografado, criptografa e vice-versa;

 - Ao criptografar, incrementa 1 no arquivo encryptedfiles.ctrl;
 - Ao descriptografar, diminui 1 no arquivo encryptedfiles.ctrl.

Ao digitar a senha, será gerado o hash usando o Bcrypt e comparado com o conteúdo do arquivo de senha.

Caso a senha esteja correta, ela será usada para gerar a chave de criptografia

## 3. Descriptografar, abrir, fechar e criptografar novamente;
Recebe os mesmos parâmetros do tópico 2, mas após descriptografar, abre o arquivo usando a devida aplicação e, quando fechar, criptografa o arquivo novamente, automaticamente.

Os arquivos aceitos para abrir uma aplicação automaticamente para fazer a leitura são:
 - **.txt**: notepad.exe (Bloco de notas);
 - **.pdf**: msedge.exe (Microsoft Edge);
 - **docx**, **doc**: winword.exe (Microsoft Word);
 - **xlsx**, **xls**, **csv**: excel.exe (Microsoft Excel).

Dentre as extensões aceitas, com exceção do **pdf**, após abrir a aplicação para visualizar o arquivo, basta fechá-la (finalizar o processo) para criptografar o arquivo novamente automaticamente.

O pdf é uma exceção pois ao rodar o msedge.exe, o código não espera o processo ser finalizado para continuar com a execução.
Portanto, descriptografa, abre a aplicação e imediatamente criptografa o arquivo novamente, antes mesmo da aplicação conseguir carregar o arquivo.
Com isso, foi necessário colocar um *input()* após o *subprocess.run()* do pdf, para impedir a execução imediata do código.
Para o tipo **pdf** será necessário dar um enter no *shell* para continuar a execução e criptografar o arquivo novamente.

Caso o usuário tente executar a 3ª opção para um arquivo não criptografado, será apresentada uma mensagem de erro informando que para usar essa opção, o arquivo precisa estar criptografado.

## Estrutura de arquivos
 - Arquivo com hash da senha
 - Arquivo com a quantidade de arquivos criptografados

## Usos Externos
 - Cryptography library (https://pypi.org/project/cryptography/)
   - From cryptography, it's going to be used Fernet and Scrypt
   - Scrypt Kdf (https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt)
 - Bcrypt module (https://pypi.org/project/bcrypt/)

## Sources
 - https://www.thepythoncode.com/article/encrypt-decrypt-files-symmetric-python
 - https://www.geeksforgeeks.org/hashing-passwords-in-python-with-bcrypt/
 - https://realpython.com/python-logging/
 - https://docs.python.org/3/library/subprocess.html