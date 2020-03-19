import sys
from math import log, gcd
from random import randint, getrandbits

def main():
    try:
        if sys.argv[1] == "--gen-keys":
            gen_keys(int(sys.argv[2]))
        
        elif sys.argv[1] == "--encrypt":
            encrypt(sys.argv[2])

        elif sys.argv[1] == "--decrypt":
            decrypt(sys.argv[2])
        else:
            print("{} - No such option", sys.argv[1])

    except (IndexError, ValueError):
        print("Wrong arguments")

def gen_keys(bits):
    # Generating two distinct primes
    key_length = int(log(2)/log(10)*bits)
    p = rand_prime(key_length)
    q = p

    while p == q:
        q = rand_prime(key_length)

    # Computing p*q which is modulus for both keys
    n = p*q

    # Computing Carmicheal's totient function: lambda(n)
    #   lambda(n) - lcm(lambda(p), lambda(q)), where lcm - least common multiple
    #   lambda(p) = phi(p) = p-1, for p being to the power of one, which holds
    #   Computing lcm using formula: lcm(p,q) = |p*q|/gcd(p,q)
    car_lambda = abs((p-1)*(q-1)) // gcd(p-1,q-1)

    # Chosing integer e to be coprime with lambda(n)
    # For security in broad setting often number 65 537 is being chosen
    # Small Hamming weight and bit-length for efficiency
    e = 65537

    # Determining d such as: d = e**-1 mod lambda(n)
    # Computing by using the Extended Euclidean for: d*e = 1 mod lambda(n)
    # Finding inverse of e mod lambda(n)
    d = euclidean_inverse(e, car_lambda)

    # Public key consists of modulus n and public exponent e
    with open ("key.pub", "w") as pub:
        pub.writelines(["n="+str(n),"\ne="+str(e)])

    # Private key consists of private exponent d
    with open("key.prv", "w") as prv:
        prv.writelines(["n="+str(n),"\nd="+str(d)])

    # Numbers p, q and lambda(n) should be discarded as they can be used to calculate d
    print("\nKeys generated and saved: ")
    print(" - key.pub")
    print(" - key.prv")

def euclidean_inverse(x, car_lambda):
    """
    step 0: modulus = aux_list[0]*x0 + rest0, p0 = 0
    step 1: x0 = aux_list[1]*rest0 + rest1, p1 = 1
    step 2: rest0 = aux_list[2]*rest1 + rest2, p2 = (p0-p1*aux_list[0])%car_lambda
    step 3: rest1 = aux_list[3]*rest2 + rest3, p3 = (p1-p2*aux_list[1])%car_lambda
    ...
    Ends when rest(n) is 0 (and previous remainder 1, if no then no inverse, but we know it exists)
    Then the inverse is equal to: p(n+2)
    """
    modulus = car_lambda
    p0, p1 = 0,1
    aux_list = []
    step = 0
    
    while True:
        if step > 1:
            p0, p1 = p1, (p0 - p1*aux_list[0]) % car_lambda
            del aux_list[0]
        
        if x == 0:
            return p1

        aux_list.append(modulus // x)    
        modulus, x = x, modulus % x   

        step += 1

def rand_candidate(key_length):
    # Generating prime candidate, with first and last bit set to 1
    # Length needs to be kept as key_length bits and number needs to be odd
    # We make or operation between prime end 1000...01 sequence
    candidate = getrandbits(key_length)
    candidate |= (1 << key_length -1) | 1
    return candidate

def rand_prime(key_length):
    # First integer that's not prime to go into loop (do while)
    prime = 4
    while not is_prime(prime):
        prime = rand_candidate(key_length)
    return prime

def is_prime(n, tests=128):
    if n == 2:
        return True
    elif n % 2 == 0 or n < 2:
        return False

    # Searching for r and s sastisfying condition: n = r*(2**s) + 1
    # Factoring out powers from n-1 till r is not odd
    r = n-1
    s = 0

    # Looping till r is odd (bitwise - faster than modulo)
    while r & 1 == 0:
        s += 1
        r //= 2
    
    # Prime is being tested for many a's to be more certain
    for i in range(tests):
        a = randint(2, n-2)  # a = [2,n-2]
        x = pow(a,r,n)       # x = a**r % n

        # If x is 1 or n-1 choose next a (no need to check)
        if x != 1 and x != n-1:
            j = 1
            # Repeating s-1 times
            while j < s and x != n-1:
                x = pow(x,2,n) # x = x**2 % n
                # If x is one than n is not prime - subgroup generator found (no algebra)
                if x == 1:
                    return False
                j += 1

            # After repeating s-1 times the last group member shall be generated (cycle)
            if x != n-1:
                return False

    return True  


def encrypt(plaintext):
    try:
        with open ("key.pub", "r") as file:
            key = file.readlines()
            n = int(key[0][2:])
            e = int(key[1][2:])

        # String is translated into byte array
        byte_plaintext = [hex(ord(char)) for char in plaintext]

        if len(byte_plaintext)*8 > len(str(bin(n))):
            print("Raw RSA encryption:")
            print("Message cannot be encrypted - more bits than the key's")
            exit()

        # Byte array is being concatenated and cast to int
        int_plaintext = int("".join(str(byte)[2:] for byte in byte_plaintext),16)
        print(hex(int_plaintext))

        # Encryption of plaintext integer number
        print(pow(int_plaintext, e, n))
    
    except FileNotFoundError:
        print("Public key not found.")
        print("Make sure that that your key is in the same directory.")
        print("To generate pair of keys: python rsa.py --gen-keys <length_in_bits>")


def decrypt(cipher):
    try:
        with open ("key.prv", "r") as file:
            key = file.readlines()
            n = int(key[0][2:])
            d = int(key[1][2:])

        # Decrytpting cipher
        hex_cipher = str(hex(pow(int(cipher), d, n)))
        print(hex_cipher)

        # Dividing decrypted hex string into bytes
        byte_cipher = [(hex_cipher[i:i+2]) for i in range(2, len(hex_cipher), 2)]

        # Translating bytes into ASCII equivalents
        print("".join(chr(int(byte,16)) for byte in byte_cipher))
        
    
    except FileNotFoundError:
        print("Private key not found.")
        print("Make sure that that your key is in the same directory.")
        print("To generate pair of keys: python rsa.py --gen-keys <length_in_bits>")


if __name__ == "__main__":
    main()