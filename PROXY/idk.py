import os  
aes_key = os.urandom(32)
iv = os.urandom(16)
print(aes_key)
print(iv)
