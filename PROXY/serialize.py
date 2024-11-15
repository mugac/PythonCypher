import os
import sys
import aes
# import pq_ntru
sys.path.append(os.path.abspath("./NTRU"))
# sys.path.append(os.path.abspath("./AES"))

from ntru import generate_keys,encrypt,decrypt

# # Use the function
# result = my_function()
# print(result)

# from ntru import generate_keys,encrypt,decrypt
generate_keys("key", mode="moderate", skip_check=True, debug=True)
# generate_keys("key", mode="moderate", skip_check=True, debug=True, check_time=True)

# example of using mode of operation
mk = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
mk_arr = aes.utils.int2arr8bit(mk, 32)
pt = 0x00112233445566778899aabbccddeeff
pt_arr = aes.utils.int2arr8bit(pt, 16)


cipher = aes.aes(mk, 256, mode='CTR', padding='PKCS#7')

# notice: enc/dec can only 'list'  !! 
ct_arr = cipher.enc(pt_arr)
print("0x"+hex(aes.utils.arr8bit2int(ct_arr))[2:].zfill(32))

pr_arr = cipher.dec(ct_arr)
print("0x"+hex(aes.utils.arr8bit2int(pr_arr))[2:].zfill(32))

# # Path to the virtual environment's Python interpreter
# venv_python = os.path.join("all", "bin", "python")  # Linux/Mac
# # venv_python = os.path.join("venv", "Scripts", "python")  # Windows

# # Path to the script to execute
# script_to_run = os.path.join("NTRU/", "ntru.py")

# generate_keys()


# # Execute the script and capture its output
# result = subprocess.run([venv_python, script_to_run], capture_output=True, text=True)

# # Get the standard output and error
# output = result.stdout
# error = result.stderr

# print("Output:", output)
# print("Error:", error)