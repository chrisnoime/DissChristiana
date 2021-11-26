
import secrets

class Server():
    def __init__(self, group_len):
        self.group_id = secrets.randbits(192)  #geração da chave de grupo

        self.group_len = group_len
        self.tags_no_servidor = []
        self.even_list = []
        self.odd_list = []

    def generate_tag_even_quote(self):       
        even = secrets.randbits(192)
        self.even_list.append(even)
        return even
        
    def generate_tag_odd_quote(self):       
        odd = secrets.randbits(192)
        self.odd_list.append(odd)
        return odd

    def generate_tag_id(self): 
        tag_ID = secrets.randbits(192)
        self.tags_no_servidor.append(tag_ID)
        return tag_ID  

    def generate_reader_ID(self):
        reader_ID = secrets.randbits(192)  
        return reader_ID
            
    def authenticate_group(self, group_id_calculated):
        if self.group_id == group_id_calculated:
            return True
        else:
            return False

    def authenticate_tag(self, id_decrypted):
        if id_decrypted in self.tags_no_servidor:
            return True
        else:
            return False
