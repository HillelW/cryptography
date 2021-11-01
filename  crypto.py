from typing import List, Tuple
import binascii
import secrets
import string


class Crypto (object):
    ######################################
    # classical cryptographic algorithms #
    ######################################

    def atbash (self, plaintext: str):
        plaintext = plaintext.upper ()
        lookup_table = {
                        'A' : 'Z', 'B' : 'Y', 'C' : 'X', 'D' : 'W', 'E' : 'V',
                        'F' : 'U', 'G' : 'T', 'H' : 'S', 'I' : 'R', 'J' : 'Q',
                        'K' : 'P', 'L' : 'O', 'M' : 'N', 'N' : 'M', 'O' : 'L',
                        'P' : 'K', 'Q' : 'J', 'R' : 'I', 'S' : 'H', 'T' : 'G',
                        'U' : 'F', 'V' : 'E', 'W' : 'D', 'X' : 'C', 'Y' : 'B', 
                        'Z' : 'A'
                       }
        cipher = ''
        for letter in plaintext:
            if letter != ' ':
                cipher += lookup_table[letter]
            else:
                cipher += ' '
        return cipher

    def mono_alphabetic_substitution (self, plaintext: str, step: int, alphabets=(string.ascii_lowercase, string.ascii_uppercase, string.digits)):
        '''
           Example Usage:
        
           plaintext = 'HELLOWORLD'
           ciphertext = crypto.mono_alphabetic_substitution (plaintext, 13) == 'URYYBJBEYQ'
           crypto.caesar (cyphertext, 13) == 'HELLOWORLD'
        '''
        def shift (alphabet: str):
            return alphabet[step:] + alphabet[:step]

        shifted_alphabets = tuple (map (shift, alphabets))
        joined_aphabets = ''.join (alphabets)
        joined_shifted_alphabets = ''.join (shifted_alphabets)
        table = str.maketrans (joined_aphabets, joined_shifted_alphabets)
        return plaintext.translate (table)

    def poly_alphabetic_substitution (self, plaintext: str, steps: List[int]):
        '''
           Example Usage:
        
           plaintext = 'HELLOWORLD'
           ciphertext = crypto.poly_alphabetic_substitution (plaintext, [15, 20]) == 'WYAFDQDLAX'
           crypto.poly_alphabetic_substitution (plaintext, [-15, -20]) == 'HELLO WORLD'
        '''
        plaintext_length = len (plaintext)
        steps_length = len (steps)
        ratio = plaintext_length / steps_length
        steps = steps * int (ratio)
        cipher_text = []
        for step, symbol in zip (steps, plaintext):
            cipher = self.mono_alphabetic_substitution (symbol, step)
            cipher_text.append (cipher)
        return ''.join (cipher_text)

    def get_poly_alphabetic_key (self, key_string: str) -> List[int]:
        '''
           Example Usage:

           crypt.get_poly_alphabetic_key ('ABC') == [0, 1, 2] 
        '''
        key = []
        for i in range (0, len (key_string)):
            element = ord(key_string[i]) - 65
            print (element)
            key.append(element)
        return key

    def string_to_int (self, secret: str) -> int:
        '''
           given a secret string, converts it to a binary
           number and returns the corresponding binary number as an int

           Example Usage:

           key = crypto.string_to_int ('SECRETKEY')
           plaintext = 'HELLOWORLD'
           ciphertext = crypto.xor_encode (plaintext, key)
           crypto.xor_decode (ciphertext, key)
        '''
        # convert string secret to binary secret
        binary_secret = secret.encode ()
        # convert binary secret to hex secret
        hex_secret = binascii.hexlify (binary_secret)
        # convert hex secret to int secret
        key = int (hex_secret, 16)
        return key
    
    def xor_encode (self, plaintext: str, key: int) -> int:
        # convert string plaintext to binary
        binary_plaintext = plaintext.encode ()
        # convert binary to hex
        hex_string = binascii.hexlify (binary_plaintext)
        # XOR hex with key
        ciphertext = int (hex_string, 16) ^ key
        return ciphertext

    def xor_decode (self, ciphertext: int, key: int) -> str:
        # XOR ciphertext with key
        xor_ciphertext_with_key = ciphertext ^ key
        # convert result to hex
        to_hex = format (xor_ciphertext_with_key, 'x')
        # pad with zeros until length is even
        evenpad = ('0' * (len (to_hex) % 2)) + to_hex
        plaintext = binascii.unhexlify (evenpad)
        return plaintext.decode ()
    
    def one_time_pad (self, plaintext: str) -> str:
        '''
           given a `plaintext` string of length n, 
           returns a secret key of lenght n.
        '''
        key = ''
        for i in range (len (plaintext)):
            key += secrets.choice ('ABCDEFGHIJKLMNOPQRSTUVWZYZ')
        return key

    def shift_encode (self, plaintext: str, key: int) -> str:
        '''a `key` of 3 yields a result equivalent to a caesar cipher.'''
        cleaned_plaintext = plaintext.upper ().replace (' ', '')
        cipher_list = []
        for symbol in cleaned_plaintext:
            int_symbol = ord (symbol) - ord ('A')
            modular_sum = (int_symbol + key) % 26
            new_symbol = chr (modular_sum + ord ('A'))
            cipher_list.append (new_symbol)
        return ''.join (cipher_list)
            
    def shift_decode (self, ciphertext: str, key: int) -> str:
        decoded_list = []
        for symbol in ciphertext:
            int_symbol = ord (symbol) - ord ('A')
            modular_sum = (int_symbol - key) % 26
            new_symbol = chr (modular_sum + ord ('A'))
            decoded_list.append (new_symbol)
        return ''.join (decoded_list)

    def affine_encode (self, plaintext: str, a: int, b: int):
        '''`
           `a` must satisfy the condition that gcd (a, 26) == 1.

           Example Usage:

           crypto.affine_encode ('ATTACK', 9, 13) == 'NCCNFZ'
           crypto.affine_decode ('NCCNFZ', 9, 13) == 'ATTACK'
        '''
        cleaned_plaintext = plaintext.upper ().replace (' ', '')
        cipher_list = []
        for symbol in cleaned_plaintext:
            int_symbol = ord (symbol) - ord ('A')
            modular_combination = ((int_symbol * a) + b) % 26
            new_symbol = chr (modular_combination + ord ('A'))
            cipher_list.append (new_symbol)
        return ''.join (cipher_list)

    def affine_decode (self, ciphertext: str, a: int, b: int):
        decoded_list = []
        modular_inverse = self.modular_inverse (a, 26)

        for symbol in ciphertext:
            int_symbol = ord (symbol) - ord ('A')
            modular_combination = ((modular_inverse * int_symbol) - b) % 26
            new_symbol = chr (modular_combination + ord ('A'))
            decoded_list.append (new_symbol)
        return ''.join (decoded_list)

    ###############################
    # number theoretic algorithms #
    ###############################

    def extended_gcd (self, a: int, b: int) -> Tuple[int, int, int]:
        '''
           given two integers `a` and `b`, returns a tuple containing gcd (a, b),
           and two integers x and y such that:

           ax + by == gcd (a,b).
        '''
        x,y, u,v = 0,1, 1,0
        while a != 0:
            q, r = b//a, b%a
            m, n = x-u*q, y-v*q
            b,a, x,y, u,v = a,r, u,v, m,n
            gcd = b
        return gcd, x, y

    def modular_inverse (self, a: int, m: int) -> int:
        '''
           given two integers `a` and `m`, returns the multiplicative inverse
           of a modulo m. such an inverse only exists if gcd (a ,m) == 1.

           Example Usage:

           crypto.modular_inverse (7, 31) == 9
        '''
        gcd, x, y = self.extended_gcd (a, m)
        if gcd != 1:
            # modular inverse does not exist
            return None 
        return x % m