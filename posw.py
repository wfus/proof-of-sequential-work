from scheme import statement, compute_posw, opening_challenge


DEFAULT_w = 10
DEFAULT_t = 10 
DEFAULT_n = 10
DEFAULT_m = 10
DEFAULT_N = 2**10 

def verifier_init(w=DEFAULT_w, t=DEFAULT_t, N=DEFAULT_N):
    return statement(w=w, t=t, N=N)


def prover_init(chi, w=DEFAULT_w, t=DEFAULT_t, N=DEFAULT_N):
    raise NotImplementedError


def verifier_challenge(w=DEFAULT_w, t=DEFAULT_t):
    return opening_challenge(w=w, t=t)


def prover_challenge():
    raise NotImplementedError    


def verifier_check():
    raise NotImplementedError    



if __name__ == '__main__':
    print('Raymond.')
    chi = verifier_init()
    phi, phi_P = prover_init(chi)
    challenge_gamma = verifier_challenge()
    prover_challenge()
    verifier_check() 


