import os 
import pyaes 
import socket 
import threading 
import hashlib 
import json 
from datetime import datetime 
 
print("Client Running") 
HOST = input('Enter Destination IP: ') 
PORT = int(input('Enter Destination Port: ')) 

try: 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.connect((HOST, PORT)) 
except ConnectionError: 
    print('Could Not Connect!') 
    exit(-1) 

key = input('AES Pre-Shared-Key For Connection: ') 
hashed = hashlib.sha256(key.encode()).digest() 
aes = pyaes.AES(hashed) 
 
def process_bytes(bytess): 
    ret = [] 
    while len(bytess) >= 16: 
        byts = bytess[:16] 
        ret.append(byts) 
        bytess = bytess[16:] 
    return ret 

def process_text(data): 
    streams = [] 
    while len(data) > 0: 
        if len(data) >= 16: 
            stream = data[:16] 
            data = data[16:] 
        else: 
            stream = data + ("~" * (16 - len(data))) 
            data = '' 
        stream_bytes = [ord(c) for c in stream] 
        streams.append(stream_bytes) 
    return streams 
 
def verify_and_display(recv_dict): 
    timestamp = recv_dict['timestamp'] 
    recv_hash = recv_dict['hash'] 
    message = recv_dict['message'] 
    mess_hash = hashlib.sha256(str(message).encode('utf-8')).hexdigest() 
    SET_LEN = 80 
    tag = '☑' if mess_hash == recv_hash else '☒' 
    spaces = SET_LEN - len(f"Received: {message}") - 1 
    if spaces > 0: 
        space = ' ' * spaces 
        sentence = f"Received: {message}{space}{tag}  {timestamp}" 
        print(sentence) 
 
class myThread(threading.Thread): 
    def __init__(self, id): 
        threading.Thread.__init__(self) 
        self.threadID = id 
 
    def stop(self): 
        self.is_alive = False 
 
    def run(self): 
        print(f"[+] Listening On Thread {self.threadID}") 
        while True: 
            try: 
                data = s.recv(1024) 
                if data: 
                    mess = '' 
                    processed_data = process_bytes(data) 
                    for dat in processed_data: 
                        decrypted = aes.decrypt(dat) 
                        for ch in decrypted: 
                            if chr(ch) != '~': 
                                mess += str(chr(ch)) 
                    try: 
                        data_recv = json.loads(mess) 
                        verify_and_display(data_recv) 
                    except: 
                        print('Unrecognized Data or Broken PIPE') 
            except ConnectionResetError: 
                print('Connection Lost!') 
 
Listening_Thread = myThread(1) 
Listening_Thread.daemon = True 
Listening_Thread.start() 
 
while True: 
    try: 
        sending_data = input("") 
    except KeyboardInterrupt: 
        s.close() 
        exit(-1) 
    if sending_data == "quit()": 
        Listening_Thread.stop() 
        s.close() 
        exit() 
    timestamp = str(datetime.now())[11:19] 
    mess_hash = hashlib.sha256(str(sending_data).encode('utf-8')).hexdigest() 
    send_data = { 
        "timestamp": timestamp, 
        "message": sending_data, 
        "hash": mess_hash 
    } 
    send_json_string = json.dumps(send_data) 
    sending_bytes = process_text(send_json_string) 
    enc_bytes = [] 
    for byte in sending_bytes: 
        ciphertext = aes.encrypt(byte) 
        enc_bytes += bytes(ciphertext) 
    s.send(bytes(enc_bytes)) 
s.close()
