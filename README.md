# serpent

Serpent cipher in the AES contest.

Author: Qian Shengyi & Songqun

## Usage

To compile

```bash
make
```

To generate a random key

```bash
./c2 --generate
```

Output (hexidecimal):

```bash
f9200a43b7eeb5e249e008e2164962dc1451ab862506c27ab801eb93113ad76c
```

To encrypt a message (string)

```bash
./c2 --encrypt "ve475" --key "f9200a43b7eeb5e249e008e2164962dc1451ab862506c27ab801eb93113ad76c"
```

Output (hexidecimal):

```bash
b94b1cc0af565b6dbace20279431f1ff
```

To decrypt a ciphertext(hexidecimal)

```bash
./c2 --decrypt "b94b1cc0af565b6dbace20279431f1ff" --key "f9200a43b7eeb5e249e008e2164962dc1451ab862506c27ab801eb93113ad76c"
```

Output (string):

```bash
ve475
```


## Cipher

Serpent cipher is the finalist in the AES contest. For the details of algroithms, see also <http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf>. We implement the cipher following the paper.


## Details

- The key length must be 256-bit. Otherwise it will be refused.
- if no key specified, random key will be used.
- Mode ECB for long string
