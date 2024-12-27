import hmac
import hashlib
import base64
import struct
import time
from Leveragers import log
from colorama import *

class Totp:
    def __init__(self, secret, algo="SHA1", digits=6, interval=30):
        self.secret = secret
        self.digits = digits
        self.interval = interval
        self.algo = algo.upper()

        if self.algo not in ["SHA1", "SHA256", "SHA512"]:
            raise ValueError(f"Unsupported algorithm. Use one of: SHA1, SHA256, SHA512.")

    @classmethod
    def gen(cls, secret, algorithm="SHA1", digits=6, interval=30):
        if not secret:
            log.err("Secret is required. Please provide a valid secret.")
            log.inf(f"Usage: {Fore.LIGHTBLACK_EX}Totp.gen(secret='<secret>', algorithm='<algorithm>', digits=<digits>, interval=<interval>){Fore.RESET}")
            return
        
        if algorithm not in ["SHA1", "SHA256", "SHA512"]:
            log.err(f"Invalid algorithm {Fore.LIGHTRED_EX}{algorithm}{Fore.RESET}. Supported algorithms are: {Fore.GREEN}SHA1, SHA256, SHA512.{Fore.RESET}")
            return
        
        return cls(secret, algo=algorithm, digits=digits, interval=interval)

    def timecnt(self):
        return int(time.time() // self.interval)

    def genhmac(self, cnt):
        key = base64.b32decode(self.secret.replace(" ", ""), casefold=True)
        cntbytes = struct.pack(">Q", cnt)
        hashfunc = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}[self.algo]
        return hmac.new(key, cntbytes, hashfunc).digest()

    def truncate(self, hmacval):
        off = hmacval[-1] & 0x0F
        trunc = hmacval[off:off + 4]
        return struct.unpack(">I", trunc)[0] & 0x7FFFFFFF

    def genotp(self):
        cnt = self.timecnt()
        return self.otpforcnt(cnt)

    def verifyotp(self, otp, look=1):
        cnt = self.timecnt()
        for i in range(-look, look + 1):
            if self.otpforcnt(cnt + i) == otp:
                return True
        return False

    def otpforcnt(self, cnt):
        hmacval = self.genhmac(cnt)
        truncval = self.truncate(hmacval)
        otp = truncval % (10 ** self.digits)
        return str(otp).zfill(self.digits)

    def output(self):
        otp = self.genotp()
        log.success(f"Generated OTP : {Fore.LIGHTBLACK_EX}{otp}{Fore.RESET}")
