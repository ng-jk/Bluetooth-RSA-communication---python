import base64
import json
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
import random
import math
import uuid
import RSA
import os

#use p=7,q=3, should get from Certificate autority
CA_e = 7
CA_d = 103
CA_n= 143
SHA256 = RSA.SHA256()

mac_addr = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
if(mac_addr != "f8:5e:a0:bd:cc:8d"):
    mac_addr = "f8:5e:a0:bd:cc:8d"
    client = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    print("Waiting for connection...")
    client.connect(("f8:5e:a0:bd:cc:8d", 7))
    print(f"Connected to: {mac_addr}")

    def receive():
        while True:
            try:
                message = client.recv(1024).decode('utf-8')  # Receive and decode the message
                decoded_message = decode_message(message)  # Process the received message
                if decoded_message:  # If decoding was successful, update the listbox
                    message_listbox.insert(tk.END, decoded_message)
            except Exception as e:
                # Log the error and close the client socket
                print(f"An error occurred: {e}")
                client.close()
                break

    def write(message):
        json_message = json.dumps(message)  # Convert the dictionary to a JSON string
        client.send(json_message.encode('utf-8'))  # Send the JSON string

else:
    server = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    server.bind((mac_addr, 7))
    server.listen(1)

    print("Waiting for connection...")
    while True:
        try:
            client, client_address = server.accept()
            break
        except:
            print("connection fail")

    print(f"Connected to: {client_address}")

    def receive():
        while True:
            try:
                message = client.recv(1024).decode('utf-8')  # Receive and decode the message
                decoded_message = decode_message(message)  # Process the received message
                if decoded_message:  # If decoding was successful, update the listbox
                    message_listbox.insert(tk.END, decoded_message)
            except Exception as e:
                # Log the error and close the client socket
                print(f"An error occurred: {e}")
                client.close()
                server.close()
                break

    def write(message):
        json_message = json.dumps(message)  
        client.send(json_message.encode('utf-8'))

def decode_message(message):
    try:
        message = json.loads(message)  # Convert JSON string to a dictionary
        if (message["type"] == "key"):
            
            #for public key
            global r_public_key
            r_public_key = message["public key"]
            global r_n
            r_n = message["n"]
            recieve_key_label.config(text=str(r_public_key))
        elif (message["type"] == "message"):

            #for message
            MD1 = RSA.RSAdecryption(message["Digital signature"], CA_d, CA_n)
            MD2 = SHA256.compute(message["content"])

            print("MD1: ",MD1)
            print("DS: ",message["Digital signature"])
            print("MD1: ", MD2)
            print("encrypted message: ",message["content"])

            if (MD1 == MD2):
                message = RSA.RSAdecryption(message["content"], key["decryption key"], key["n"])
                return message
            else:
                print("message not match")
            
            tk.messagebox.showwarning("Warning", "decode error")

        elif(message["type"] == "file"):

            #for file

            MD1 = RSA.RSAdecryption(message["Digital signature"], CA_d, CA_n)
            MD2 = SHA256.compute(message["key"])

            print("DS: ",message["Digital signature"])
            print("MD1: ",MD1)
            print("MD2: ", MD2)
            print("encrypted key: ",message["key"])

            if (MD1 == MD2):

                #get aes key
                AES_key = RSA.RSAdecryption(message["key"],key["decryption key"], key["n"])
                print("AES key",AES_key)

                #get file data
                file_data = RSA.aes_decrypt(message["content"], AES_key)
                print(file_data)

                #get file name
                file_name = message["file name"]

                try:
                    recieve_file = open(file_name,"xb")
                except IOError:
                    recieve_file = open(file_name,"wb")
                
                recieve_file.write(file_data)
                recieve_file.close()

                return file_name
            else:
                print("key not match")

        else:
            tk.messagebox.showwarning("Warning", "Unknown message type")
    except json.JSONDecodeError:
        tk.messagebox.showwarning("Warning", "Invalid message format")
    return True


def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def auto_generate_pq():
    p_entry.delete(0, tk.END)
    q_entry.delete(0, tk.END)
    while True:
            p = random.choice(range(10,50))
            q = random.choice(range(10,50))
            if (p==q):
                continue
            if (is_prime(p) and is_prime(q)):
                break
    p_entry.insert(0, p)
    q_entry.insert(0, q)

def generate_key():
    p = eval(p_entry.get())
    q = eval(q_entry.get())
    if (p_entry.get() == "") or (q_entry.get() == ""):
        tk.messagebox.showwarning("Warning", "Please enter p & q")
    else:
        if (p==q):
            tk.messagebox.showwarning("Warning", "q and q is same")
        elif (is_prime(p) and is_prime(q)):
            n = p * q
            fi = (p - 1) * (q - 1)
            e = 2
            while True:
                if math.gcd(e, fi) == 1:
                    break
                e += 1
                
            for d in range(1, fi):
                if (e * d) % fi == 1:
                    break
            
            global key
            key ={
                "encryption key":e,
                "decryption key":d,
                "n":n
            }
            private_label.config(text = d)
            public_label.config(text = e)
        else:
            tk.messagebox.showwarning("Warning", "q and q is not prime number")

def send_public_key():
    message={
        "type":"key",
        "public key":key["encryption key"],
        "n":key["n"]
    }
    print("send_public_key : success")
    write(message)

def send_message():
    message = m_entry.get()
    encrypted_message = RSA.RSAencryption(message,r_public_key,r_n)
    MD1 = SHA256.compute(encrypted_message)
    DS = RSA.RSAencryption(MD1, CA_e, CA_n)
    print("MD1: ",MD1)
    print("DS: ",DS)
    message ={
        "type":"message",
        "content": encrypted_message,
        "Digital signature":DS
    }
    write(message)
    tk.messagebox.showinfo("Success")

def browseFiles():
    filename = filedialog.askopenfilename(initialdir = "/",
                                          title = "Select a File",
                                          filetypes = (("Text files",
                                                        "*.txt*"),
                                                       ("all files",
                                                        "*.*")))
      
    # Change label contents
    f_entry.insert(0,filename)

def send_file():

    #get file content
    file_path = f_entry.get()
    file_name = file_path.split('/')[-1]
    with open(file_path, "rb") as file:
        plaintext = file.read()
        print("plaintext : ",plaintext)
    AES_key = os.urandom(16)
    print("AES_key",AES_key)
    ciphertext= RSA.aes_encrypt(plaintext, AES_key)

    #RSA encryption
    AES_key = base64.b64encode(AES_key).decode('utf-8')
    encrypted_key = RSA.RSAencryption(AES_key,r_public_key,r_n)
    MD1 = SHA256.compute(encrypted_key)
    DS = RSA.RSAencryption(MD1, CA_e, CA_n)

    #make into dictionary
    print("AES_MD1: ",MD1)
    print("AES_DS: ",DS)
    print("ciphertext",ciphertext)
    message ={
        "type":"file",
        "key": encrypted_key,
        "Digital signature":DS,
        "file name":file_name,
        "content":ciphertext,
    }
    write(message)
    tk.messagebox.showinfo("Success")


receive_thread = threading.Thread(target=receive)
receive_thread.daemon = True  # Ensure the thread exits when the main program does
receive_thread.start()

# Main Application Window
root = tk.Tk()
root.title("RSA Encryption")
root.geometry("600x700")
root.resizable(False, False)

# p Entry
tk.Label(root, text="Enter p:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
p_entry = tk.Entry(root, width=20)
p_entry.grid(row=0, column=1, padx=10, pady=10)

# q Entry
tk.Label(root, text="Enter q:").grid(row=0, column=2, padx=10, pady=10, sticky="w")
q_entry = tk.Entry(root, width=20)
q_entry.grid(row=0, column=3, padx=10, pady=10)

# Auto-generate p & q Button
auto_button = tk.Button(root, text="Auto Generate p & q", command=auto_generate_pq)
auto_button.grid(row=0, column=4, pady=10)

# Send Encryption Key Button
send_key_button = tk.Button(root, text="gennerate Encryption and decryption Key", command=generate_key)
send_key_button.grid(row=1, column=0, columnspan=2,pady=10, padx=10)
send_key_button = tk.Button(root, text="send Encryption Key(public key)", command=send_public_key)
send_key_button.grid(row=1, column=2, columnspan=2,pady=10, padx=10)

tk.Label(root, text="the encryption key:").grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="w")
private_label = tk.Label(root, text="")
private_label.grid(row=2, column=2, columnspan=1,padx=10, pady=10, sticky="w")

tk.Label(root, text="the decryption key:").grid(row=2, column=3, columnspan=2, padx=10, pady=10, sticky="w")
public_label = tk.Label(root, text="")
public_label.grid(row=2, column=5, columnspan=1, padx=10, pady=10, sticky="w")

tk.Label(root, text="encryption key recieve").grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="w")
recieve_key_label = tk.Label(root, text="")
recieve_key_label.grid(row=3, column=2, columnspan=1, padx=10, pady=10, sticky="w")

# Message Listbox
tk.Label(root, text="message").grid(row=4, column=0, padx=10, pady=10,columnspan=2, sticky="w")
message_listbox = tk.Listbox(root, height=10, width=80)
message_listbox.grid(row=5, column=0, columnspan=5, padx=10, pady=10)
m_entry = tk.Entry(root, width=80)
m_entry.grid(row=6, column=0, columnspan=5, padx=10, pady=10)

# send message button
message_button = tk.Button(root, text="send message",command=send_message)
message_button.grid(row=8, column=0, columnspan=6,pady=10)

# send file button
f_entry = tk.Entry(root, width=80)
f_entry.grid(row=9, column=0, columnspan=5, padx=10, pady=10)
browse_button = tk.Button(root, text="browse",command=browseFiles)
browse_button.grid(row=10, column=0, columnspan=3,pady=10)
file_button = tk.Button(root, text="send file",command=send_file)
file_button.grid(row=10, column=1, columnspan=3,pady=10)

# Start the application
root.mainloop()
