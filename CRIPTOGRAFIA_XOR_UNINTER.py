#OBS: Para não passar do limite de 3 páginas, foi usado técnicas de atribuição de múltiplas variáveis e compreensão de listas. Além de limitar o dicionário ASCII apenas p/ os caracteres IMPRIMÍVEIS.

#Dicionário relacionando os caracteres da tabela ASCII com seu respectivo código decimal
ascii_code = {'0': 48, '1': 49, '2': 50, '3': 51, '4': 52, '5': 53, '6': 54, '7': 55, '8': 56, '9': 57, 'a': 97, 'b': 98, 'c': 99, 'd': 100, 'e': 101, 'f': 102, 'g': 103, 'h': 104, 'i': 105, 'j': 106, 'k': 107, 'l': 108, 'm': 109, 'n': 110, 'o': 111, 'p': 112, 'q': 113, 'r': 114, 's': 115, 't': 116, 'u': 117, 'v': 118, 'w': 119, 'x': 120, 'y': 121, 'z': 122, 'A': 65, 'B': 66, 'C': 67, 'D': 68, 'E': 69, 'F': 70, 'G': 71, 'H': 72, 'I': 73, 'J': 74, 'K': 75, 'L': 76, 'M': 77, 'N': 78, 'O': 79, 'P': 80, 'Q': 81, 'R': 82, 'S': 83, 'T': 84, 'U': 85, 'V': 86, 'W': 87, 'X': 88, 'Y': 89, 'Z': 90, '!': 33, '"': 34, '#': 35, '$': 36, '%': 37, '&': 38, "'": 39, '(': 40, ')': 41, '*': 42, '+': 43, ',': 44, '-': 45, '.': 46, '/': 47, ':': 58, ';': 59, '<': 60, '=': 61, '>': 62, '?': 63, '@': 64, '[': 91, '\\': 92, ']': 93, '^': 94, '_': 95, '`': 96, '{': 123, '|': 124, '}': 125, '~': 126, ' ': 32, '\t': 9, '\n': 10, '\r': 13, '\x0b': 11, '\x0c': 12}
#Função p/ converter decimal em binário: O n° é dividido consecutivamente até ser menor que 1. A cada vez, seu módulo é adicionado a uma string que será invertida no final.
def dec_to_bin(num):
    bin = ''
    while num >= 1:
        bin += f'{num % 2}'
        num //= 2
    #Enquanto o valor for menor que 8bits, adicionar um 0 no início
    while len(bin) < 8:
        bin = bin + '0'
    return bin[::-1]
#Função p/ converter binário em decimal: Baseado na fórmula (abc)β = (a*β**2 + b*β**1 + c*β**0)10. Onde β é o comprimento da string
def bin_to_dec(bin):
    pot, dec = len(bin) -1, 0
    for value in bin:
        dec += (int(value))* 2**pot
        pot -= 1
    return dec
#Função p/ converter decimal em caractere: Através de um laço for nos itens do dicionário ascii_code, que retorna a chave do valor desejado
def dec_to_char(num):
    for key, value in ascii_code.items():
        if value == num:
            return key
#Valores iniciais que serão atribuidos como variáveis de controle para a função abaixo
chave_value, count_msg = 0, 0
#Função p/ cifrar o binário através do método XOR: Para cada dígito do binário, verificar se é igual ao dígito de mesma posição na chave (caso sim, o novo dígito é 0)
#Onde para cada execução da função, é alterado qual valor da chave que será comparado.
#EXEMPLO - CHAVE: 123
#MENSAGEM:      HELLO WORLD
#COMPARAÇÃO:    12312312312
def xor_cypher(bin):
    global chave_value, count_msg
    index, bin_xor = 0, ''

    if chave_value >= len(chave):
        chave_value = 0
    elif count_msg >= len(mensagem):
        count_msg, chave_value = 0, 0

    for num in bin:
        if num == chave[chave_value][index]:
            bin_xor += '0'
        else:
            bin_xor += '1'
        index += 1
    chave_value, count_msg = chave_value + 1, count_msg + 1
    return bin_xor
#Informar string que será criptografada
mensagem = input('Informe a mensagem a ser criptografada:')
#É criado uma lista com cada dígito do RU, que é convertido para um inteiro e posteriormente binário
chave = [dec_to_bin(int(key)) for key in input('Informe o seu RU:')]
#Definindo dicionários que serão utilizados posteriormente
msg_crypt_bin, msg_crypt_chr= [], []
#Laço for para cifrar cada letra da variável mensagem
for letra in mensagem:
    #conversão da letra para o decimal correlato na tabela ASCII e posteriormente p/ binário (com XOR aplicado)
    binario_codificado = xor_cypher(dec_to_bin(ascii_code[letra]))
    #Cada valor é adicionado em uma lista, tanto em binário quanto do caractere equivalente na tabela ASCII
    msg_crypt_chr.append(dec_to_char(bin_to_dec(binario_codificado)))
    msg_crypt_bin.append(binario_codificado)
#IMPRESSÃO DOS VALORES NA TELA
print('\nCRIPTOGRADO_BINARIO:')
[print(char_bin, end=' ') for char_bin in msg_crypt_bin]
print('\n\nCRIPTOGRADO_CHAR_ASCII:')
[print(bin_char, end=' ') for bin_char in msg_crypt_chr]
print('\n')
#Caso o usuário decida descriptografar, a cifra é aplicada novamente na mensagem criptografada, através do comparador XOR
decisao = input('Deseja descriptografar a mensagem novamente? [Y/N]')
if decisao in ('S', 's', 'SIM', 'sim', 'Sim', 'Y', 'y', 'YES', 'Yes', 'yes'):
    msg_decrypt_bin, msg_decrypt_chr = [], []
    for item in msg_crypt_bin:
            binario_decodificado = xor_cypher(item)
            #Os valores são armazenados em novas listas que serão tratadas e impressas na tela
            msg_decrypt_chr.append(dec_to_char(bin_to_dec(binario_decodificado)))
            msg_decrypt_bin.append(binario_decodificado)

    print('\nDESCRIPTOGRADO_BINARIO:')
    [print(char_bin, end=' ') for char_bin in msg_decrypt_bin]
    print('\n\nDESCRIPTOGRADO_CHAR_ASCII:')
    [print(bin_char, end=' ') for bin_char in msg_decrypt_chr]
    print('\n')
