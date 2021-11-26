import time
import matplotlib.pyplot as plt
from matplotlib import rcParams
import numpy as np
import tqdm
from hwcounter import Timer, count, count_end

from reader_ok import Reader
from server_ok import Server
from tag_ok import Tag

#parametros dos gráficos
rcParams["savefig.dpi"] = 150
fontsize = 13
rcParams['font.family'] = 'serif'
rcParams['font.sans-serif'] = ['Times New Roman']
rcParams['font.size'] = fontsize
rcParams['mathtext.fontset'] = 'stix'
rcParams['axes.titlesize'] = fontsize
rcParams['axes.labelsize'] = fontsize


class Protocol():
    def __init__(self, group_length):
        self.server = Server(group_length) #inicialização do servidor
        self.tags = []
        reader_quote = self.server.group_id

        #inicialização das etiquetas, recebimento das quotas
        for _ in range(group_length):
            odd = self.server.generate_tag_odd_quote()
            even = self.server.generate_tag_even_quote()
            tag_ID = self.server.generate_tag_id()
            tag = Tag(tag_ID, even, odd)
            reader_quote ^= even
            self.tags.append(tag)
        #inicializa o leitor
        self.reader = Reader(self.server.generate_reader_ID(), reader_quote) 

    #as etiquetas enviam as suas quotas para o leitor que confere os hashes das quotas, e se 
    # forem corretos, calcula a identidade de grupo
    def calculate_group_id(self):
        for tag in self.tags:
            self.reader.read_tag_quote(tag.send_quote())
            if self.reader.read_tag_hash(tag.send_hash()) == True:
                pass
            else: 
                print("etiqueta falsa")
        return self.reader.group_quote
    #leitor envia a identidade do grupo para autenticação no servidor
    def authenticate_group(self):
            if self.server.authenticate_group(self.reader.authenticate_with_server()) == True:
                #print("autenticação coletiva correta")
                pass
            else:
                #print("autenticação coletiva falhou")
                pass
    
    #envia a identidade do grupo
    def get_group_id(self):
        return self.group_id
    
    #etapa de autenticação individual
    def individual_authentication(self):
        for tag in self.tags: #para cada etiqueta do grupo
            # geração das chaves e verificação da assinatura da chave das etiquetas
            if self.reader.verify_signature(tag.sign_key(), 
            tag.serialized_tag_public_key_ECDH, tag.tag_public_key_ECDSA) == True: 
                #define o valor do contador
                CTR=1
                #envia a chave ECDH do leitor para a etiqueta
                received_reader_key = self.reader.send_reader_public_key_ECDH() 
                #a etiqueta gera a chave compartilhada ECDH e encripta a identidade dela
                cipher_text = tag.encrypt(tag.generate_shared_key(received_reader_key), CTR.to_bytes(3, 'big')) 
                (iv, ciphertext, encryptor_tag) = cipher_text 
                
                #o leitor gera a chave compartilhada ECDH 
                shared_key = self.reader.generate_shared_key(tag.send_tag_public_key_ECDH())
                #o leitor decripta a identidade da etiqueta
                plain_text = self.reader.decrypt(shared_key, CTR.to_bytes(3, 'big'), iv, ciphertext, encryptor_tag)
                if self.server.authenticate_tag(int(plain_text)) == True:
                    #print("autenticação individual correta")
                    pass
                else:
                    #print("autenticação individual falhou porque a identidade não foi localizada")
                    break

            else: 
                #print("autenticação falhou porque a assinatura da etiqueta está incorreta")
                break
            

if __name__ == '__main__':

    #lista para armazenar as amostras do experimento
    experiments_list = [] #autenticação coletiva - tempo
    experiments_list2 = [] #autenticação individual - tempo

    #loop para coletar amostras no experimento
    for _ in tqdm.tqdm(range(1000)):
        #lista que armazena os valores de tempo de processamento na etapa de autenticação coletiva
        authentication_group_durations = [] 
        #lista que armazena os valores de tempo de processamento na etapa de autenticação individual
        authentication_ind_durations = []

        #execução do protocolo para diferentes quantidades de etiquetas, 
        # teste da escalabilidade do protocolo. a complexidade de tempo na autenticação está 
        # sendo coletada através da função time()

        number_of_tags = range(2, 101) #número de etiquetas na amostra

        for group_len in number_of_tags:
            #etapa de inicialização
            group = Protocol(group_len)
            #etapa de autenticação coletiva
            group.calculate_group_id()
            tic = time.time()
            group.authenticate_group() 
            toc = time.time()
            authentication_group_durations.append(toc-tic)
            experiments_list.append(authentication_group_durations)

            #etapa de autenticação individual
            tac = time.time()
            group.individual_authentication()
            toe = time.time()
            authentication_ind_durations.append(toe-tac)
            experiments_list2.append(authentication_ind_durations)


    # plotagem dos resultados do experimento
    #para a etapa de autenticação individual
    experiments_array = np.array(experiments_list)
    experiments_mean = experiments_array.mean(axis=0)
    experiments_std = experiments_array.std(axis=0)
    print(experiments_std.shape)

    # plotagem incluindo a média, desvio padrão e intervalo de confiança
    plt.plot(number_of_tags, authentication_group_durations)
    plt.fill_between(number_of_tags, experiments_mean + experiments_std, experiments_mean - experiments_std, alpha=0.5)

     #definições do gráfico
    plt.title('Nº de etiquetas vs tempo de processamento')
    plt.xlabel('Quantidade de etiquetas')
    plt.ylabel('Tempo de processamento na etapa de aut. colet.')
    plt.savefig('teste_c.png')
    #para a etapa de autenticação individual

    # plotagem dos resultados do experimento
    experiments_array2 = np.array(experiments_list2)
    experiments_mean2 = experiments_array2.mean(axis=0)
    experiments_std2 = experiments_array2.std(axis=0)
    print(experiments_std2.shape)


      # plotagem incluindo a média, desvio padrão e intervalo de confiança
    plt.plot(number_of_tags, authentication_ind_durations)
    plt.fill_between(number_of_tags, experiments_mean2 + experiments_std2, experiments_mean2 - experiments_std2, alpha=0.5)

    #definições do gráfico
    plt.title('Nº de etiquetas vs tempo de processamento')
    plt.xlabel('Quantidade de etiquetas')
    plt.ylabel('Tempo de processamento na etapa de aut. ind.')
    plt.savefig('teste_a.png')

    #printa a média e o desvio padrão
    print("a média de tempo na autenticação coletiva é", sum(authentication_group_durations)/len(authentication_group_durations))
    print("a média de tempo na autenticação individual é", sum(authentication_ind_durations)/len(authentication_ind_durations))
    print("o desvio padrão de tempo na etapa de autenticação coletiva é", np.std(experiments_array2))

    
    #faz a regressão pelo método dos mínimos quadrado
    from scipy.optimize import least_squares
    
    x0 = 2.42e-6 #valor esperado calculado
    
    def reta(_x0):
        print(_x0)
        return np.array([_x0[0] - duration for duration in authentication_group_durations])

    sol = least_squares(reta,x0)
    print("as abcissas são", sol.x)
    print("fasnfoasnfo são", sol.cost)