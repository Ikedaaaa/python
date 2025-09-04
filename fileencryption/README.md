# fileencryption
Projeto desenvolvido para criptografar arquivos usando senha

## Necessidade
Gostaria de ter alguns arquivos criptografados mas não queria baixar uma aplicação.
Acredito que desenvolver algo por conta própria poderia ser mais seguro, sabendo como o programa foi desenvolvido.
Também seria bom aproveitar a oportunidade para praticar desenvolvimento em python

## Funcionamento
A intenção é que, ao rodar o script, sejam apresentadas quatro opções:
 1. Definir/Redefinir senha para criptografia;
 2. Criptografar algum arquivo;
 3. Descriptografar algum arquivo;
 4. Descriptografar um arquivo, abri-lo (launch application), e quando fechar, criptografar novamente;

Será usada a criptografia simétrica, ou seja, a mesma chave usada para criptografar o conteúdo, será usada para descriptografar.

Foi importado o módulo Cryptography para realizar criptografia utilizando AES-256 nos modos:
 - CBC com HMAC SHA256 para arquivos menores que 100 MiB;
 - GCM para arquivos superiores a 100 MiB.

## 1. Definir/Redefinir senha para criptografia
 - Se não tiver senha definida, pede input da senha e confirmação (digitar a senha duas vezes e comparar, como é feito em diversos formulários de sign in), e escreve seu hash em um arquivo.
 - Se tiver, pede a senha antiga, verifica no arquivo o hash da senha e então chama a função de definição de nova senha.

### Algoritmo de hash
Por questões de segurança, o algoritmo de hash usado será o Bcrypt, para que seja possível definir o Work Factor, seja usado um Salt e aumente muito a dificuldade de quebrar a senha

### Input de senha - getpass
Os inputs de senha serão feitos através do módulo getpass.

Com isso, qualquer texto digitado pelo usuário em um input de senha não será refletido no terminal, não revelando a senha digitada.
Pode parecer confuso, como se o teclado não estivesse funcionando, ou como se estivesse travado, porém o texto está sendo captado, só não está sendo mostrado de volta.

Além disso, qualquer input de senha é convertido para bytearray por se tratar de um objeto mutável,
sendo possível zerar os bytes em memória para que não fique exposta.

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

### Seleção de arquivos
**Inputs**:
 - O primeiro input é para definir se o input dos arquivos será feito
  1. Utilizando filedialog/File Explorer com tkinter para selecionar o(s) arquivos;
  2. Digitar o caminho dos arquivos manualmente.

É possível, através do arquivo de configuração, escolher um método padrão:
  0. Não definido. Será apresentado o input para escolher um método
  1. Input manual. Irá apresentar o input da seção abaixo "Input Manual" direto;
  2. Input com File Explorer. Irá apresentar a seção abaixo "Utilizando File Explorer" direto;

**Utilizando File Explorer**
Será aberta uma janela do File Explorer para selecionar os arquivos desejados (Somente funciona seleção múltipla entre arquivos de uma mesma pasta).
A janela é semelhante a aberta ao tentar fazer upload de algum arquivo em um site.

**Input Manual**
  - Selecionando essa opção, o primeiro input será para definir se será feito o input de múltiplos arquivos:
    1. 1 para múltiplos arquivos
    2. Qualquer outro número para somente um arquivo.
  - Caso a opção de múltiplos arquivos seja escolhida, haverá um segundo input para dar opção entre fazer o input dos arquivos manualmente, ou usando um arquivo de texto:
    1. 1 para utilizar um arquivo de texto. (Esse arquivo deve conter o caminho completo de cada arquivo, um em cada linha);
    2. Qualquer outro número para fazer input dos arquivos manualmente. Basta digitar 0 para parar com os inputs.
  - Escolhendo a opção de input usando um arquivo, será necessário digitar:
    - O caminho do arquivo, com ele incluso (e.g.: C:/Users/<user>/Desktop/files.txt).
  - Para qualquer outra opção, o input do(s) arquivos deverá ser:
    - O caminho do arquivo, com ele incluso (e.g.: C:/Users/<user>/Desktop/file_to_encrypt.txt);
    - Caso o arquivo esteja no mesmo diretório do script, basta digitar o nome do arquivo.
 
### Após seleção de arquivos
Após o input dos arquivos, será apresentado o input: 
  - **A senha (usando getpass)**.

  - Caso as opções **3 ou 4**, para **Descriptografar**, forem selecionadas, e o arquivo não estiver criptografado, será apresentado um erro.
  - Caso a opção **2** for selecionada e o arquivo já estiver criptografado, criptografa o arquivo já criptografado.

 - Ao criptografar, incrementa 1 no arquivo encryptedfiles.ctrl;
 - Ao descriptografar, diminui 1 no arquivo encryptedfiles.ctrl.

Ao digitar a senha, será gerado o hash usando o Bcrypt e comparado com o conteúdo do arquivo de senha.

Caso a senha esteja correta, ela será usada para gerar a chave de criptografia.

O KDF escolhido é o Argon2id por ser o mais recomendado para novas aplicações por questões de segurança.
Os parâmetros escolhidos para o Argon2id são:
  - 2GB de consumo de memória;
  - 10 iterações;
  - Paralelismo de 4 threads.

São parâmetros bem pesados e que tornam o processo de Key Derivation bem lento (~3-4 segundos).

**Caso múltiplos arquivos tenham sido selecionados**
Será apresentado um input para derivar uma chave diferente para cada arquivo selecionado.
Isso será um processo bem lento para fazer isso para cada arquivo, sendo recomendado para arquivos mais sensíveis.
Para arquivos não sensíveis, não é um grande problema derivar apenas uma chave e utilizá-la para criptografar todos os arquivos selecionados.

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
 - Arquivo de configuração

## Arquivo de configuração

**time_ctrl**=1 ( >= 1 - Cronometra o tempo para checar a senha com Bcrypt, derivar a senha e o tempo do processo inteiro. 0 para deixar desabilitado).
**file_input**=0 (Já foi explicado acima)

Seção **[PROGRAMS]**
Definir um programa de escolha para abrir arquivos com cada extensão

## Usos Externos
- Cryptography library (https://pypi.org/project/cryptography/)
- Cryptography documentation (https://cryptography.io/en/latest/)
  - From cryptography, it's going to be used AES256 for encryption:
    - https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.AES256
  - CBC and GCM modes of encryption:
    - https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CBC
    - https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
  - Argon2id for KDF:
    - https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.argon2.Argon2id
  - HMAC to authenticate using SHA256:
    - https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/#cryptography.hazmat.primitives.hmac.HMAC
- Bcrypt module (https://pypi.org/project/bcrypt/)

## Sources
 - https://www.thepythoncode.com/article/encrypt-decrypt-files-symmetric-python
 - https://www.geeksforgeeks.org/hashing-passwords-in-python-with-bcrypt/
 - https://realpython.com/python-logging/
 - https://docs.python.org/3/library/subprocess.html
 - https://stackoverflow.com/questions/66663179/how-to-use-windows-file-explorer-to-select-and-return-a-directory-using-python
 - https://docs.python.org/3/library/dialog.html#module-tkinter.filedialog
 - https://chatgpt.com/