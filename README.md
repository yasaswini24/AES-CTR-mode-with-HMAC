# AES-CTR-mode-with-HMAC

_**Alice:**_
Alice has an initial symmetric key k1. For every message Mi, she performs the following operations
1. Compute the ciphertext: Ci = Enc(ki, Mi). 
2. Individual HMAC: Si = HMAC(ki, Ci).
3. Aggregate HMAC: S1,i = H(S1, i-1 || Si).
4. Update ki+1 = H(ki) and delete Ki, Si, S1, i-1.
5. Send <C1, C2, …, Cn> , S1, n to Bob via ZeroMQ.

_**Bob:**_
For every ciphertext Ci, Bob computes:
1. Individual HMAC: Si = HMAC(ki, Ci).
2. Aggregate HMAC: S1,i = H(S1, i-1 || Si).
3. Update ki+1 = H(ki).
If the final aggregate HMAC matches with the one that the client sent, then for every ciphertext Ci compute:
a. Recover plaintext Mi = Dec(ki, Ci).
b. Update ki+1 = H(ki).

After computing the plaintexts, write them to a file.
Otherwise, report that an error occurred (the authentication process went wrong!).
