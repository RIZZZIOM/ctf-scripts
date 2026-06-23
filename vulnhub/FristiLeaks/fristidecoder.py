import base64, codecs

def fristidecoder(str):
    enc1 = codecs.decode(str, 'rot13')
    rev_enc = enc1[::-1]
    enc2 = base64.b64decode(rev_enc).decode()
    print(f"The string is: {enc2}")

mystring = input("Enter the string: ")
fristidecoder(mystring)