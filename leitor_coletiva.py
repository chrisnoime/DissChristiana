# -*- coding: utf-8 -*-
"""
Created on Thu Oct  8 10:24:37 2020

@author: Dell
"""

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
numero_etiquetas=4 #xxxxxxxxxxxxxxxxxxxXXXXXXXXXXXXXXXXXXx length do clients

quota_par_recebida=[]
HMAC_recebida=[]

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
                     
            quota_length=154 #comprimento da quota
            HMAC_length=55 #comprimento do HMAC
            
            
            # Define um dicionário de usuários com o ID, a quota, a chave púlica da etiqueta e o texto cifrado
            user = {'Quota_par':client_socket.recv(quota_length)} 
                    #,'HMAC':client_socket.recv(HMAC_length)
            print('Nova conexão aceita de {}:{}, Dispositivo {}'.format(*client_address, user))
        
            # Add accepted socket to select.select() list
            sockets_list.append(client_socket)
            
            # Also save username and username header
            clients[client_socket] = user
           # client_socket.send(len(chave_publica_do_leitor_ECDH_serializada).to_bytes(4, 'big')+chave_publica_do_leitor_ECDH_serializada+len(chave_publica_do_leitor_ECDH_serializada).to_bytes(4, 'big')+assinatura)
            

            #Decodifica as quotas par e sua verificação recebidas e as armazena numa lista
            quota_par_recebida.append(user['Quota_par'].decode('utf-8'))
            
            for i in range(len(quota_par_recebida)):
                quota_par=quota_par_recebida[i]
                chave_grupo=chave_grupo^int(quota_par)
    
            print("A chave desse grupo é:", chave_grupo)
            
            #Decodifica os HMAC e as armazena numa lista
            #HMAC_recebida.append(user['HMAC'].decode('utf-8'))
            
            
            #Verificação da HMAC
            #verificacao=chave_publica_recebida_ECDSA.verify(assinatura_recebida, chave_da_etiqueta_ECDH, ec.ECDSA(hashes.SHA3_256()))
            #if verificacao!=None:
             #   print('assinatura ECDSA não é válida')
             #   sys.exit()


#----------------------------------------------------------Etapa de autenticação coletiva----------------------------------------------------------
    #Cálculo da chave do grupo
            
    #Envia a chave do grupo para o servidor para verificação XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     #Recebe a resposta de autenticação. Se for autenticado prossegue, se não encerra a conexão.