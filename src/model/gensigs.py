#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import ed25519  # https://ed25519.cr.yp.to/python/ed25519.py
from random import randrange

# Generates random inputs and their correct results for testing

skfile = open('./skfile.dat', 'w')
pkfile = open('./pkfile.dat', 'w')
mfile = open('./mfile.dat', 'w')
sfile = open('./sfile.dat', 'w')
rfile = open('./rfile.dat', 'w')
keyfile = open('./keyfile.dat', 'w')
ramfile = open('./ramfile.dat', 'w')
smfile = open('./smfile.dat', 'w')

for i in range(100):
    if i == 0:
        sk = ed25519.H("FOX1FOX2FOX3FOX4".encode('utf-8'))[0:32]
        M = "hello".encode('utf-8')
    else:
        sk = randrange(0, 2**256 - 1)
        sk = ('%064x' % sk).decode('hex')
        M = randrange(0, 2**256 - 1)
        M = ('%064x' % M).decode('hex')
    A = ed25519.publickey(sk)
    sig = ed25519.signature(M, sk, A)
    
    key = ed25519.Hint(sk)
    h = ed25519.H(sk)
    a = 2**(ed25519.b-2) + sum(2**i * ed25519.bit(h,i) for i in range(3,ed25519.b-2))
    r = ed25519.Hint(''.join([h[i] for i in range(ed25519.b/8,ed25519.b/4)]) + M)
    R = ed25519.scalarmult(ed25519.B,r)
    RAM = ed25519.Hint(ed25519.encodepoint(R) + A + M)

#     print 'sk: %s' % sk.encode('hex')
#     print 'M: %s' % M.encode('hex')
#     print 'A: %s' % A.encode('hex')
#     print 'R: %s' % sig[:32].encode('hex')
#     print 'S: %s' % sig[32:].encode('hex')

    keyfile.write(('%0128x' % key) + '\n')
    ramfile.write(('%0128x' % RAM) + '\n')
    smfile.write(('%0128x' % r) + '\n')

    skfile.write(sk.encode('hex') + '\n')
    mfile.write(M.encode('hex') + '\n')
    pkfile.write(A.encode('hex') + '\n')
    rfile.write(sig[:32].encode('hex') + '\n')
    sfile.write(sig[32:].encode('hex') + '\n')

