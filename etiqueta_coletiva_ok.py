# -*- coding: utf-8 -*-
"""
Created on Thu Oct  8 10:24:36 2020

@author: Dell
"""

import socket
import errno
import os  
import cryptography
import sys
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

#-------------------------------------------------------Constantes----------------------------------------------------------------------


IP = "127.0.0.1"
PORT = 1234


#valores recebidos na etapa de inicialização

quota = int(input('Qual a sua quota par?'))

#--------------------------------------------------------Cálculo do Hash---------------------------------------------------------

#Cria um hash para a quota utilizando o SHA-256
digest = hashes.Hash(hashes.SHA3_256())
digest.update(quota.to_bytes(24, 'big'))
hashe=digest.finalize() #serializa o hash para envio

#------------------------------------------------------Parte da comunicação------------------------------------------------------------------------
# Cria uma soquete da família IPv4 e conexão TCP

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conecta a um dado endereço IP e porta 
client_socket.connect((IP, PORT))

# Coloca a conexão em um estado de não bloqueio, então .recv() não vai bloquear, só retornar uma exceção
client_socket.setblocking(False)

while True:         
  
        # Cria um loop para o recebimento de mensagens, mas o usuário precisa informar que houve conexão

  
    evento=input('Ocorreu conexão com o leitor?')
    
    # Se um evento ocorreu, envia a quota e o HMAC para o leitor
    if evento:
        
        client_socket.send(hashe+f"{quota}".encode('utf-8'))
        sys.exit()

   
       