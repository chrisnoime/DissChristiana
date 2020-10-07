import socket
import select
import sys

import secrets
  

#------------------------------------------------------------Constantes--------------------------------------------------------------
Ne=0 #numero total de etiquetas
Ng=0 #numero de grupos
Ne_input=[]
list_etiquetas_grupo=[]#numero de etiquetas nos grupos
lista_leitores=[] #lista com os leitores
lista_etiquetas=[] #lista com as etiquetas
quotas_par=[] #lista com as quotas pares
quotas_impar=[] #lista com as quotas impares
ID_grupos=[] #lista com as identidades dos grupos
XOR_quotas=[] #
XOR_quota=0
quotas_especiais=[]
quotas_leitores=[]#lista com as quotas dos leitores
verificacao=[]#valor para verificar se o compartilhamento secreto ta batendo
quota_especial=0
quota_leitor=0
ID_grupo=0
ID_leitor=0
ID_etiqueta=0
ID=0
grupo=0

CTRE=1 #contador da quantidade de etiquetas conectadas
CTRL=1 #contador da quantidade de leitores conectados

ID_length = 3
group_length=3
type_length=10

IP = "127.0.0.1"
PORT = 1234

#----------------------------------------------------------Recebe as entradas do usuário---------------------------------------------------
Ng_input=input("Qual o número de grupos?")
Ng=int(Ng_input)

#for k in range(Ng):
#a=input("Qual o número de etiquetas no grupo?")
    #Ne_input.append=a

#-------------------------------------------------------------Parte da criptografia-------------------------------------------------------

#-------------------------------------------------------------Parte do compartilhamento secreto----------------------------------------
ID_grupo=secrets.randbits(192)

    
#gera um conjunto crescente de Ng grupos e suas IDs
for i in range(Ng):
    
    ID_grupos.append(secrets.randbits(192))
    list_etiquetas_grupo.append(i)
    
#Aqui começa a geração das quotas das etiquetas e dos leitores

  
    for j in range(list_etiquetas_grupo[i]):
       quotas_par.append(secrets.randbits(192))
       quotas_impar.append(secrets.randbits(192))
       #print('As quotas deste grupo são:', quotas)
       XOR_quota=XOR_quota^quotas_par[j]
       XOR_quota=XOR_quota^quotas_impar[j]
       
    quotas=quotas_par+quotas_impar   
    XOR_quotas.append(XOR_quota) 
    quota_especial=XOR_quota
    quotas_especiais.append(quota_especial)
    ID=ID_grupos[i]
    quota_leitor=ID^quota_especial
    quotas_leitores.append(quota_leitor)
    verificacao.append(quota_leitor^quota_especial)


print('As identidades dos grupos são:', ID_grupos)      
print ('As quantidades de etiquetas nos grupos são:', list_etiquetas_grupo)   
print('O XOR das quotas:', XOR_quotas)          
#print('O XOR das quotas das etiquetas é:', quotas_especiais)    
print('As quotas dos leitores são:', quotas_leitores)
print('As quotas das etiquetas são:', quotas)

if verificacao==ID_grupos:
    print('A verificação da ID dos grupos está ok')
else: print('não está batendo')

#calcula o número total de etiquetas no sistema Ne
for num in range(0, len(list_etiquetas_grupo)): 
    Ne = Ne + list_etiquetas_grupo[num] 
   
print("Ne é", Ne) 


#----------------------------------------------------------------Parte da comunicação--------------------------------------------------

# Cria uma soquete da família IPv4 e conexão TCP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Conecta, o servidor informa ao OS que vai usar essa porta e endereço IP 
server_socket.bind((IP, PORT))

# O servidor escuta novas conexões
server_socket.listen()

# lista de soquetes para select.select()
sockets_list = [server_socket]

# Lista de clientes conectados, o soquete é a chave, o header e o tipo de dispositivo são os dados
clients = {}

print(f'Esperando por conexões em {IP}:{PORT}...')


#------------------------------------------------------Aqui começa o loop-------------------------------------------------------------------------------


while True:

    # Inicializa o select
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)


    # Itera sobre os soquetes notificados
    for notified_socket in read_sockets:

        # Se o soquete detectado é um soquete pedindo uma nova conexão- deve-se aceitá-la
        if notified_socket == server_socket:

            # Aceitar a nova conexão, dá um novo cliente soquete com o seu endereço
            client_socket, client_address = server_socket.accept()

            # Lida com as mensagens recebidas
            
            # recebe a primeira mensagem com o ID, tipo de dispositivo e grupo ao qual pertence
            ID_recebido = client_socket.recv(ID_length)
        
            # Se nenhum dado foi recebido, disconectar
            if not len(ID_recebido):
                socket.SHUT_RDWR

            # Converte o ID recebido para um inteiro para processamento
            ID = int(ID_recebido)
        
            # Define um dicionário de usuários com o ID, o tipo de dispositivo e o grupo ao qual pertence
            user = {'ID': ID, 'Grupo':int(client_socket.recv(group_length)), 'Tipo de dispositivo': client_socket.recv(type_length)}           
            print(user)
            
            #guarda o valor do grupo desse dispositivo
            grupo_recebido = user['Grupo']
            
            # Adiciona o soquete aceito na lista select.select() 
            sockets_list.append(client_socket)
            
            # E salva os dados desse soquete numa lista de clientes
            clients[client_socket] = user
           
             # Verifica se é uma etiqueta ou um leitor ou um dispositivo não reconhecido
            #se for uma etiqueta envia as quotas dela
            if user['Tipo de dispositivo'].decode('utf-8')=='etiqueta':
                CTRE=+1
                dados=f"{quotas_par[CTRE]}".encode('utf-8')+b'//'+f"{quotas_impar[CTRE]}".encode('utf-8')
                client_socket.send(b'As suas quotas sao:'+ dados)
                
            #se for um leitor envia o ID do grupo dele e a quota referente a esse grupo   
            elif user['Tipo de dispositivo'].decode('utf-8')=='leitor':
                CTRL=+1
                dados=f"{quotas_leitores[CTRL],ID_grupos[CTRL]}".encode('utf-8')
                client_socket.send(b'A sua quota e a ID do seu grupo sao:'+ dados)
            #se não for uma etiqueta nem um leitor, é um dispositivo não reconhecido e termina a conexão
            else: #acho que aqui devia ser uma exceção
                print("Dispositivo não reconhecido")
                socket.SHUT_RDWR
                continue

            print('Nova conexão aceita de {}:{}, ID {}'.format(*client_address, user['ID']))
            print(lista_leitores, lista_etiquetas)

        # Se não, um soquete já conectado está enviando uma mensagem
        else:

            # Recebe a messagem
            message = client_socket.recv(192)
            print("O dispositivo com a ID", user['ID'], "mandou a mensagem", message) 
            






    