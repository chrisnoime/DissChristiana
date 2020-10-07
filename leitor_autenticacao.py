import socket
import select
import errno
import os  
import cryptography
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives import serialization
  

#------------------------------------------Constantes---------------------------------------------------------------------------

IP = "127.0.0.1"
PORT = 1234

ID=111

# Gera as chaves do ECDH
#gera a chave privada
chave_privada_do_leitor_ECDH = ec.generate_private_key(ec.SECP192R1())
print("A chave privada do leitor é:", chave_privada_do_leitor_ECDH)

#gera a chave pública e serializa para bytes para poder enviar
chave_publica_do_leitor_ECDH= chave_privada_do_leitor_ECDH.public_key()
print("A chave pública do leitor é:", chave_publica_do_leitor_ECDH)

chave_publica_do_leitor_ECDH_serializada = chave_publica_do_leitor_ECDH.public_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PublicFormat.SubjectPublicKeyInfo)
chave_publica_do_leitor_ECDH_serializada.splitlines()[0]

#Gera as chaves do ECDSA
chave_privada_do_leitor_ECDSA = ec.generate_private_key(ec.SECP192R1())
chave_publica_do_leitor_ECDSA = chave_privada_do_leitor_ECDSA.public_key()

#Gera a assinatura da chave pública do ECDH usando o ECDSA
assinatura = chave_privada_do_leitor_ECDSA.sign(chave_publica_do_leitor_ECDH_serializada,ec.ECDSA(hashes.SHA256()))
print('A assinatura da chave pública ECDH do leitor é:', assinatura)



#-------------------------------------------Váriaveis---------------------------------------------------------------------------
CTR=0
quota=2746577512355205859157840216526864179689440502875054356288
quota_nativa=2746577512355205859157840216526864179689440502875054356289
K_ID=0
chave=27465775123552058591578402
numero_etiquetas=4

quota_par_recebida=[]
HMAC_recebida=[]
chaves_etiquetas_ECDH=[]
chaves_etiquetas_ECDSA=[]
chaves_compartilhadas=[]



#-------------------------------------------Cria a função para decriptar o AES---------------------------------------------------------------------

def decrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()

#------------------------------------------Área de testes----------------------------------------------------------------------



#dados recebidos na etapa de inicialização, como o cada leitor pode ter acesso a vários grupos, isso deve ser uma lista

quota_leitor=1543081927340809415937676767331069949295057160263597329568
chave_grupo=quota_leitor

#mas soh pra testar
quotas_etiquetas=[]
for i in range(numero_etiquetas):
    
    quotas_etiquetas.append(secrets.randbits(192))
    
quotas_leitor=[0] 

quotas_leitor[0]=quota_leitor^quotas_etiquetas[0]^quotas_etiquetas[1]^quotas_etiquetas[2]^quotas_etiquetas[3]

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
            
            # recebe a primeira mensagem com os comprimentos dos dados a serem recebidos  no formato de uma tupla e cria as variáveis com os tamanhos         
            total_length = client_socket.recv(6)
            lengths=tuple(total_length) #tupla com todos os comprimentos de dados a serem recebidos
            
            ID_length=total_length[0] #comprimento do ID
            quota_length=total_length[1] #comprimento da quota
            Pk_ECDH_length=total_length[2] #comprimento da chave pública ECDH
            Pk_ECDSA_length=total_length[3] #comprimento da chave pública ECDSA
            HMAC_length=total_length[4] #comprimento do HMAC
            signature_length=total_length[5] #comprimento da assinatura da chave pública ECDH
            
            
            
            # Define um dicionário de usuários com o ID, a quota, o HMAC da quota, a chave púlica da etiqueta e o texto cifrado
            user = {'ID': client_socket.recv(ID_length), 'Quota_par':client_socket.recv(quota_length), 
                    'chave_publica_da_etiqueta_ECDH':client_socket.recv(Pk_ECDH_length), 
                    'chave_publica_da_etiqueta_ECDSA':client_socket.recv(Pk_ECDSA_length), 
                    'HMAC_quota':client_socket.recv(HMAC_length),
                    'assinatura':client_socket.recv(signature_length)
                    }  
            
                
            #Verificação do HMAC
            
            #print(K_ID.verify(b'olar'))

            
            print('Nova conexão aceita de {}:{}, Dispositivo {}'.format(*client_address, user))
        
            # Add accepted socket to select.select() list
            sockets_list.append(client_socket)
            
            # Also save username and username header
            clients[client_socket] = user
            client_socket.send(len(chave_publica_do_leitor_ECDH_serializada).to_bytes(4, 'big')+chave_publica_do_leitor_ECDH_serializada+len(chave_publica_do_leitor_ECDH_serializada).to_bytes(4, 'big')+assinatura)
            

            #Decodifica as quotas par e sua verificação recebidas e as armazena numa lista
            quota_par_recebida.append(user['Quota_par'].decode('utf-8'))
            HMAC_recebida.append(user['HMAC_quota'])
            
            #a chave pública ECDH e ECDSA têm que ser deserializadas
            chave_da_etiqueta_ECDH=user['chave_publica_da_etiqueta_ECDH']
            chave_publica_recebida_ECDH = serialization.load_pem_public_key(chave_da_etiqueta_ECDH)
            chaves_etiquetas_ECDH.append(chave_publica_recebida_ECDH)
            
            chave_da_etiqueta_ECDSA=user['chave_publica_da_etiqueta_ECDSA']
            chave_publica_recebida_ECDSA = serialization.load_pem_public_key(chave_da_etiqueta_ECDSA)
            chaves_etiquetas_ECDSA.append(chave_publica_recebida_ECDSA)
            
            assinatura_recebida=user['assinatura']
            
            #Verificação da assinatura ECDSA
            verificacao=chave_publica_recebida_ECDSA.verify(assinatura_recebida, chave_da_etiqueta_ECDH, ec.ECDSA(hashes.SHA256()))
            if verificacao!=None:
                print('assinatura ECDSA não é válida')
                sys.exit()

#----------------------------------------------------------Etapa de autenticação coletiva----------------------------------------------------------
    #Cálculo da chave do grupo
            for i in range(len(quota_par_recebida)):
                quota_par=quota_par_recebida[i]
                chave_grupo=chave_grupo^int(quota_par)
    
            print("A chave desse grupo é:", chave_grupo)
    #Envia a chave do grupo para o servidor para verificação XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     #Recebe a resposta de autenticação. Se for autenticado prossegue, se não encerra a conexão.
    
#---------------------------------------------------------------------ECDH-------------------------------------------------------------------
 
#Gera as chave compartilhadas
#for i in range(len(chaves_etiquetas)): 
    #chaves_compartilhadas.append(chave_privada_do_leitor.exchange(ec.ECDH(), user['chave_publica_da_etiqueta']))
            chave_compartilhada=chave_privada_do_leitor_ECDH.exchange(ec.ECDH(),chave_publica_recebida_ECDH)
            print("A chave compartilhada criada pelo ECDH para o AES é:", chave_compartilhada)

        # Se não, um soquete já conectado está enviando uma mensagem
        else:  
             # Recebe as messagens
             conferidor=client_socket.recv(3)
             # Se não receber, desconecta desse cliente
             if conferidor is False:
                print('Closed connection from: {}'.format(clients[notified_socket][ID].decode('utf-8')))

                # Remove-o da lista socket.socket()
                sockets_list.remove(notified_socket)

                # e da lista de usuários
                del clients[notified_socket]

                continue
             if conferidor==b'ok':
               mensagem =  {'CTR':client_socket.recv(3), 'iv':client_socket.recv(12), 'tag':client_socket.recv(16), 'texto_cifrado':client_socket.recv(120)}
               # Encontra o usuário pela lista de soquetes notificados para identificá-lo
               user = clients[notified_socket]
               texto_decifrado=decrypt(chave_compartilhada, mensagem['CTR'], mensagem['iv'],mensagem['texto_cifrado'],mensagem['tag'])
               print(f'Mensagem recebida de {user["ID"]}', texto_decifrado)
             
             
        
#--------------------------------------------------------Compartilhamento entre as etiquetas------------------------------------------------         
            # Itera nos clientes conectados e repassa a mensagem recebida em broadcast
            # for client_socket in clients:

                # Menos para o que enviou
                #if client_socket != notified_socket:

                    # Envia as informações
                    #client_socket.send(user[ID] + mensagem)   


            
            