This Python script is designed to decode encoded passwords found on the FristiLeaks machine from VulnHub. The script takes an encoded string as input and reveals the original password through a series of decoding steps. 

- Link to writeup: https://ziomsec.com/writeups/vulnhub/fristileaks/

## How It Works

The FristiLeaks Password Decoder follows these steps to decode the password:
1. **ROT13 Decoding:** The script first decodes the input string using the ROT13 cipher, which shifts each letter 13 places in the alphabet.
2. **Reversal:** The decoded string is then reversed.
3. **Base64 Decoding:** Finally, the reversed string is decoded using Base64 to reveal the original password.

## Usage

1. **Install Python**
2. **Download the Script**
3. **Run the Script**
   
   ```bash
   python fristidecoder.py
   ```

4. **Enter the Encoded String:** When prompted, enter the encoded string that you want to decode.
5. **🔐 View the Decoded Password:** The script will print the decoded password.

---