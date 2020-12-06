# -*- coding: utf-8 -*-
"""
Created on Mon Sep 28 15:25:31 2020

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
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)


#------------------------------------------Constantes ---------------------------------------------------------------------------


IP = "127.0.0.1"
PORT = 1234

ID=124 #lembrar que varia pra cada dispositivo


#-------------------------------------Parte da comunicação------------------------------------------------------------------------

# Cria uma soquete da família IPv4 e conexão TCP

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conecta a um dado endereço IP e porta 
client_socket.connect((IP, PORT))

# Coloca a conexão em um estado de não bloqueio, então .recv() não vai bloquear, só retornar uma exceção
client_socket.setblocking(False)

# Informa o tipo de dispositivo
tipo_de_dispositivo = b'etiqueta'

client_socket.send(f"{ID}".encode('utf-8') +tipo_de_dispositivo)

while True:
                          
# O usuário precisa informar que houve conexão
    evento = input('Ocorreu conexão?')

    
    # Se ocorreu um evento, envia uma mensagem
    if evento:
        
        client_socket.send(f"{evento}".encode('utf-8'))
    

    try:
        # Aguarda o recebimento dos dados das quotas e grupo
        while True:
            data = client_socket.recv(192)
            print(data) 
            sys.exit()
    

    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()

        # We just did not receive anything
        continue

    except Exception as e:
        # Any other exception - something happened, exit
        print('Reading error: '.format(str(e)))
        sys.exit()
        


        
