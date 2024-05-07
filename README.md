## SECURE HASH FUNCTION (SHA)
## AIM:
Develop a program to implement Secure Hash Algorithm (SHA-1)
## SECURED HASH ALGORITHM-1 (SHA-1):
```
Step 1: Append Padding Bits….
Message is “padded” with a 1 and as many 0’s as necessary to bring the
message length to 64 bits fewer than an even multiple of 512.
Step 2: Append Length....
64 bits are appended to the end of the padded message. These bits hold the
binary format of 64 bits indicating the length of the original message.
Step 3: Prepare Processing Functions….
SHA1 requires 80 processing functions defined as:
f(t;B,C,D) = (B AND C) OR ((NOT B) AND D) ( 0 <= t <= 19)
f(t;B,C,D) = B XOR C XOR D (20 <= t <= 39)
f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D) (40 <= t<=59)
f(t;B,C,D) = B XOR C XOR D (60 <= t <= 79)
Step 4: Prepare Processing Constants....
SHA1 requires 80 processing constant words defined as:
K(t) = 0x5A827999 ( 0 <= t <= 19)
K(t) = 0x6ED9EBA1 (20 <= t <= 39)
K(t) = 0x8F1BBCDC (40 <= t <= 59)
K(t) = 0xCA62C1D6 (60 <= t <= 79)
Step 5: Initialize Buffers….
SHA1 requires 160 bits or 5 buffers of words (32 bits):
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0
Step 6: Processing Message in 512-bit blocks (L blocks in total message)….
This is the main task of SHA1 algorithm which loops through the padded
and appended message in 512-bit blocks.
Input and predefined functions: M[1, 2, ..., L]: Blocks of the padded and appended
message f(0;B,C,D), f(1,B,C,D), ..., f(79,B,C,D): 80 Processing Functions K(0), K(1),
..., K(79): 80 Processing Constant Words
H0, H1, H2, H3, H4, H5: 5 Word buffers with initial values
Step 6: Pseudo Code….
For loop on k = 1 to L
(W(0),W(1),...,W(15)) = M[k] /* Divide M[k] into 16 words */
For t = 16 to 79 do:
W(t) = (W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)) <<< 1
A = H0, B = H1, C = H2, D = H3, E = H4
For t = 0 to 79 do:
 TEMP = A<<<5 + f(t;B,C,D) + E + W(t) + K(t) E = D, D = C,
C = B<<<30, B = A, A = TEMP
 End of for loop
 H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E
 End of for loop
Output:
H0, H1, H2, H3, H4, H5: Word buffers with final message digest
```
## PROGRAM
```python

import hashlib

def main():
    try:
        md = hashlib.sha1()
        print("Message digest object info: ")
        print(" Algorithm = " + md.name)
        print(" ToString = " + str(md))
        
        input_str = "".encode('utf-8')
        md.update(input_str)
        output = md.digest()
        print()
        print("SHA1(\"" + input_str.decode('utf-8') + "\") = " + bytes_to_hex(output))
        
        input_str = "san".encode('utf-8')
        md.update(input_str)
        output = md.digest()
        print()
        print("SHA1(\"" + input_str.decode('utf-8') + "\") = " + bytes_to_hex(output))
        
        input_str = "sanjay".encode('utf-8')
        md.update(input_str)
        output = md.digest()
        print()
        print("SHA1(\"" + input_str.decode('utf-8') + "\") = " + bytes_to_hex(output))
        print("")
    except Exception as e:
        print("Exception: " + str(e))

def bytes_to_hex(b):
    hex_digits = '0123456789ABCDEF'
    buf = ""
    for byte in b:
        buf += hex_digits[(byte >> 4) & 0x0F]
        buf += hex_digits[byte & 0x0F]
    return buf

if __name__ == "__main__":
    main()

```
## OUTPUT:

![image](https://github.com/sanjay3061/Ex-04/assets/121215929/a18bdd3a-6128-4a0b-a9e0-41cb91197b31)



## RESULT:
Thus SHA was implemented successfully.






  ## DIGITAL SIGNATURE STANDARD

## AIM:
To write a python program to implement the signature scheme named digital
signature standard (Euclidean Algorithm).
## ALGORITHM:
```
STEP-1: Alice and Bob are investigating a forgery case of x and y.
STEP-2: X had document signed by him but he says he did not sign that document digitally.
STEP-3: Alice reads the two prime numbers p and a.
STEP-4: He chooses a random co-primes alpha and beta and the x’s original signature x.
STEP-5: With these values, he applies it to the elliptic curve cryptographic equation to obtain
y
STEP-6: Comparing this ‘y’ with actual y’s document, Alice concludes that y is a
forgery.
```
## PROGRAM: (Digital Signature Standard)
```python
import random

class DSA:
    @staticmethod
    def get_next_prime(ans):
        test = int(ans)
        while not DSA.is_probable_prime(test):
            test += 1
        return test

    @staticmethod
    def is_probable_prime(n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Miller-Rabin primality test
        def miller_rabin(n, d):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                return True
            while d != n - 1:
                x = pow(x, 2, n)
                d *= 2
                if x == 1:
                    return False
                if x == n - 1:
                    return True
            return False

        # Write n as (2^r)*d + 1
        d = n - 1
        while d % 2 == 0:
            d //= 2
        for _ in range(k):
            if not miller_rabin(n, d):
                return False
        return True

    @staticmethod
    def find_q(n):
        start = 2
        while not DSA.is_probable_prime(n):
            while n % start != 0:
                start += 1
            n //= start
        return n

    @staticmethod
    def get_gen(p, q, rand_obj):
        h = random.randint(2, p - 2)
        return pow(h, (p - 1) // q, p)

    @staticmethod
    def main():
        rand_obj = random.SystemRandom()
        p = DSA.get_next_prime("10600")
        q = DSA.find_q(p - 1)
        g = DSA.get_gen(p, q, rand_obj)

        print("\n simulation of Digital Signature Algorithm \n")
        print("\n global public key components are:\n")
        print("\np is:", p)
        print("\nq is:", q)
        print("\ng is:", g)

        x = rand_obj.randint(2, q - 1)
        y = pow(g, x, p)
        k = rand_obj.randint(2, q - 1)
        r = pow(g, k, p) % q
        hash_val = rand_obj.randint(2, p - 1)
        k_inv = pow(k, -1, q)
        s = (k_inv * (hash_val + x * r)) % q

        print("\nsecret information are:\n")
        print("x (private) is:", x)
        print("k (secret) is:", k)
        print("y (public) is:", y)
        print("h (rndhash) is:", hash_val)

        print("\n generating digital signature:\n")
        print("r is:", r)
        print("s is:", s)

        w = pow(s, -1, q)
        u1 = (hash_val * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

        print("\nverifying digital signature (checkpoints):\n")
        print("w is:", w)
        print("u1 is:", u1)
        print("u2 is:", u2)
        print("v is:", v)

        if v == r:
            print("\nsuccess: digital signature is verified!\n", r)
        else:
            print("\nerror: incorrect digital signature\n")


if __name__ == "__main__":
    DSA.main()

```
## OUTPUT:

![image](https://github.com/sanjay3061/Ex-04/assets/121215929/40abc26c-e666-4fcd-9683-20672ff1ea0e)

## RESULT:
Thus program to implement the signature scheme named digital signature standard (Euclidean Algorithm) is implementeds successfully.
