from posw import *
from util import sha256, sha256H
import matplotlib.pyplot as plt
import time

time_posw = []
time_verify = []
for n in range(1, 15):
    chi = statement()
    start = time.time()
    G = compute_posw(chi, n=n)
    diff = time.time() - start
    print(diff)
    time_posw.append(diff)
    gamma = opening_challenge(n=n)
    tau = compute_open(chi, G, gamma)
    start = time.time()
    compute_verify(chi, G.node[BinaryString(0, 0)]['label'], gamma, tau, n=n)
    diff = time.time() - start
    print(diff)
    time_verify.append(diff)
print(time_posw)
print(time_verify)
plt.plot(range(1, 15), time_posw)
plt.show()
plt.plot(range(1, 15), time_verify)
plt.show()