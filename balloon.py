import hashlib

hash_function = hashlib.sha256

"""
Concatenate all arguments and hash them together
"""
def hash_func(*args):
    # Convert everything to bytes first
    byte_args = b''
    for arg in args:
        if not isinstance(arg, bytes):
            str_rep = str(arg) 
            byte_args += str.encode(str_rep)
        else:
            byte_args += arg
    return hash_function(byte_args).digest()


"""
First step of the algorithm. Fill up a buffer with
pseudorandom bytes derived from the password and salt
by computing repeatedly the hash function on a combination
of the password and the previous hash.
"""
def expand(buf, cnt, space_cost):
    for s in range(1, space_cost):
        buf.append(hash_func(cnt, buf[s - 1]))
        cnt += 1


"""
Mixing step of the balloon hash. 
    - cnt:         security parameter from paper
    - delta:       number of random blocks to mix with
    - salt:        string representation of salt
    - space_cost:  size of the buffer
    - time_cost:   number of mixing rounds
Returns nothing, updates buffer in place.
"""
def mix(buf, cnt, delta, salt, space_cost, time_cost):
    for t in range(time_cost):
        for s in range(space_cost):
            buf[s] = hash_func(cnt, buf[s - 1], buf[s])
            cnt += 1
            for i in range(delta):
                other  = int.from_bytes(hash_func(cnt, salt, t, s, i), byteorder='little') % space_cost
                cnt += 1
                buf[s] = hash_func(cnt, buf[s], buf[other])
                cnt += 1


"""
Returns last value in the buffer. Returns a string. 
"""
def extract(buf):
    return buf[-1]


"""
Implementation of the balloon function from https://eprint.iacr.org/2016/027.pdf
Does the following steps to hash a value with a specific time cost and space cost. 
    * expand
    * mix
    * extract
Takes in password and salt (the naming convention of the paper) as strings, takes in 
ints for space and time costs. Delta is an int for number of mixing blocks.
"""
def balloon(pw, salt, space, time, delta=3):
    buf = [hash_func(0, pw, salt)]
    cnt = 1
    expand(buf, cnt, space)
    mix(buf, cnt, delta, salt, space, time)
    return extract(buf)


"""
Takes in two strings, password and the salt, and computes the balloon
hash with some space cost and time cost. Will return a string. 
"""
def balloon_hash(password, salt, space=30, time=30, delta=5):
    pw = password.encode('utf-8')
    slt = salt.encode('utf-8')
    return balloon(pw, slt, space, time, delta=delta)


if __name__ == '__main__':
    print("Raymond.")
    print(balloon_hash("HEH", "NOTHING PERSONNEL"))