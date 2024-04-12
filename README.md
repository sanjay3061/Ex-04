## SECURE HASH FUNCTION (SHA)
## DATE :
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
def sha1(message):
    # Step 1: Append Padding Bits
    original_message = message
    message += b'\x80'  # Append a single '1' bit
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'  # Append '0' bits until length % 512 == 448

    # Step 2: Append Length
    message += (len(original_message) * 8).to_bytes(8, byteorder='big')

    # Step 5: Initialize Buffers
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Step 6: Processing Message in 512-bit blocks
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        words = [int.from_bytes(chunk[j:j+4], byteorder='big') for j in range(0, 64, 4)]

        # Step 6: Pseudo Code
        for t in range(16, 80):
            words.append((words[t-3] ^ words[t-8] ^ words[t-14] ^ words[t-16]) << 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        for t in range(80):
            if t < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif t < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif t < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (a << 5) + f + e + words[t] + k & 0xFFFFFFFF
            e = d
            d = c
            c = b << 30
            b = a
            a = temp

        # Update buffers
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Output the final message digest
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

# Example usage:
message = b"Hello, World!"
hashed_message = sha1(message)
print("SHA-1 hash of '{}' is: {}".format(message, hashed_message))

```
## OUTPUT:
![image](https://github.com/sanjay3061/Ex-04/assets/121215929/beae4709-506d-4b58-94dd-8568d4a36bf4)



## RESULT:
Thus SHA was implemented successfully.






  ## DIGITAL SIGNATURE STANDARD

## AIM:
To write a C program to implement the signature scheme named digital
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
```
import java.util.*;
import java.math.BigInteger;
class dsaAlg {
final static BigInteger one = new BigInteger("1");
final static BigInteger zero = new BigInteger("0");
public static BigInteger getNextPrime(String ans)
{
BigInteger test = new BigInteger(ans);
while (!test.isProbablePrime(99))
e:
{
test = test.add(one);
}
return test;
}
public static BigInteger findQ(BigInteger n)
{
BigInteger start = new BigInteger("2");
while (!n.isProbablePrime(99))
{
while (!((n.mod(start)).equals(zero)))
{
start = start.add(one);
}
n = n.divide(start);
}
return n;
}
public static BigInteger getGen(BigInteger p, BigInteger q,
Random r)
{
BigInteger h = new BigInteger(p.bitLength(), r);
h = h.mod(p);
return h.modPow((p.subtract(one)).divide(q), p);
}
public static void main (String[] args) throws
java.lang.Exception
{
Random randObj = new Random();
BigInteger p = getNextPrime("10600"); /* approximate
prime */
BigInteger q = findQ(p.subtract(one));
BigInteger g = getGen(p,q,randObj);
System.out.println(" \n simulation of Digital Signature
Algorithm \n");
System.out.println(" \n global public key components
are:\n");
System.out.println("\np is: " + p);
System.out.println("\nq is: " + q);
System.out.println("\ng is: " + g);
BigInteger x = new BigInteger(q.bitLength(), randObj);
x = x.mod(q);
BigInteger y = g.modPow(x,p);
BigInteger k = new BigInteger(q.bitLength(), randObj);
k = k.mod(q);
BigInteger r = (g.modPow(k,p)).mod(q);
BigInteger hashVal = new BigInteger(p.bitLength(),
randObj);
BigInteger kInv = k.modInverse(q);
BigInteger s = kInv.multiply(hashVal.add(x.multiply(r)));
s = s.mod(q);
System.out.println("\nsecret information are:\n");
System.out.println("x (private) is:" + x);
System.out.println("k (secret) is: " + k);
System.out.println("y (public) is: " + y);
System.out.println("h (rndhash) is: " + hashVal);
System.out.println("\n generating digital signature:\n");
System.out.println("r is : " + r);
System.out.println("s is : " + s);
BigInteger w = s.modInverse(q);
BigInteger u1 = (hashVal.multiply(w)).mod(q);
BigInteger u2 = (r.multiply(w)).mod(q);
BigInteger v = (g.modPow(u1,p)).multiply(y.modPow(u2,p));
v = (v.mod(p)).mod(q);
System.out.println("\nverifying digital signature
(checkpoints)\n:");
System.out.println("w is : " + w);
System.out.println("u1 is : " + u1);
System.out.println("u2 is : " + u2);
System.out.println("v is : " + v);
if (v.equals(r))
{
System.out.println("\nsuccess: digital signature is
verified!\n " + r);
}
else
{
System.out.println("\n error: incorrect digital
signature\n ");
}
}
}
```
## OUTPUT:
![image](https://github.com/IsaacAIML2023/Ex-04/assets/158465339/337034c5-ea1c-4332-a753-7c5b679325f2)

## RESULT:
Thus program to implement the signature scheme named digital signature standard (Euclidean Algorithm) is implementeds successfully.
