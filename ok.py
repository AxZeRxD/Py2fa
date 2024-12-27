from T2fa import Totp

def test():

    secret = "khxi okcj zqtc j54b 2t2x awcr xx3x g4ln"
    # print(f"Testing with secret: {secret}")

    pyauthsha1 = Totp.gen(secret=secret, algorithm="SHA1", digits=6, interval=30)
    if not pyauthsha1:
        return

    otpsha1 = pyauthsha1.genotp() # This will generate the OTP
    # print(f"Generated OTP (SHA1): {otpsha1}")
    pyauthsha1.output() # This will print the OTP 

    if pyauthsha1.verifyotp(otpsha1):
        print(f"OTP (SHA1) is valid.")
    else:
        print(f"OTP (SHA1) is invalid.")




######################################################################################################################################
######################################################################################################################################



    pyauthsha256 = Totp.gen(secret=secret, algorithm="SHA256", digits=6, interval=30)
    if not pyauthsha256:
        return

    otpsha256 = pyauthsha256.genotp() # This will generate the OTP
    # print(f"Generated OTP (SHA256): {otpsha256}")
    pyauthsha256.output()  # This will generate the OTP

    if pyauthsha256.verifyotp(otpsha256):
        print(f"OTP (SHA256) is valid.")
    else:
        print(f"OTP (SHA256) is invalid.")



######################################################################################################################################
######################################################################################################################################



    pyauthsha512 = Totp.gen(secret=secret, algorithm="SHA512", digits=6, interval=30)
    if not pyauthsha512:
        return

    otpsha512 = pyauthsha512.genotp() # This will generate the OTP
    # print(f"Generated OTP (SHA512): {otpsha512}")
    pyauthsha512.output() # This will generate the OTP

    if pyauthsha512.verifyotp(otpsha512):
        print(f"OTP (SHA512) is valid.")
    else:
        print(f"OTP (SHA512) is invalid.")

if __name__ == "__main__":
    test()
