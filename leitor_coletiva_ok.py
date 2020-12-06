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

quota_par_recebida=[]
Hash_recebida=[]

#Pede de input para o usuário qual o número de etiquetas do grupo desse leitor
numero_etiquetas=input("Qual o número de etiquetas do grupo desse leitor?")
Ne=int(numero_etiquetas)

#Pede de input para o usuário qual a quota desse leitor
quota=input("Qual a quota desse leitor?")
quota_leitor=int(quota)


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
                     
            quota_length=57 #comprimento da quota codificada em utf-8
            Hash_length=32 #comprimento do hash
            
            
            # Define um dicionário de usuários com o ID, a quota e o HMAC
            user = {'Hash':client_socket.recv(Hash_length),'Quota_par':client_socket.recv(quota_length)} 
                    
            print('Nova conexão aceita de {}:{}, Dados {}'.format(*client_address, user))
        
            # Adiciona o socket na lista de clientes
            sockets_list.append(client_socket)
            
            # Inclui os dados desse dicionario no de clientes
            clients[client_socket] = user
         

            #Decodifica as quotas par e sua hash recebidas e as armazena em listas
            quota_recebida=int(user['Quota_par'])
            quota_par_recebida.append(quota_recebida)
            Hash_recebida.append(user['Hash'])
                        
            #Verificação do Hash
            digest = hashes.Hash(hashes.SHA3_256())
            digest.update(quota_recebida.to_bytes(24, 'big'))
            verificacao=digest.finalize()
            
            if verificacao!=user['Hash']:
                print('a hash não é válida')
                sys.exit()
            
            
            print("o número de etiquetas conectadas é:",len(sockets_list)-1)
            
            #Se o número de etiquetas conectadas se igualar ao número total de etiquetas do grupo desse leitor
            if len(sockets_list)==Ne+1:
                #Cálculo da chave do grupo
                chave_grupo=quota_leitor
                for i in range(len(quota_par_recebida)):
                    chave_grupo=chave_grupo^int(quota_par_recebida[i])
                print("A chave desse grupo é:", chave_grupo)  


#----------------------------------------------------------Comunicação com o servidor----------------------------------------------------------

            
    #Envia a chave do grupo para o servidor para verificação 
     #Recebe a resposta de autenticação. Se for autenticado prossegue, se não encerra a conexão.