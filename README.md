# Py2fa - Simple and Easy-to-Use TOTP Generator

**Py2fa** is a lightweight and easy-to-use Time-Based One-Time Password (TOTP) generator. This library is perfect for developers who need to integrate TOTP functionality into their tools, whether for authentication or security-related applications. With Py2fa, you can easily generate TOTP tokens for use in requests-based tools, APIs, and many other applications that require secure one-time passwords.

## Features

- **Easy Integration**: Py2fa allows for simple integration with your Python projects.
- **Multiple Algorithm Support**: Supports SHA-1, SHA-256, and SHA-512 algorithms for TOTP generation.
- **Flexible**: Customize the number of digits and time intervals for OTP generation.
- **Cross-Platform**: Works on all major platforms where Python is supported.
- **Secure**: Implements TOTP as per RFC 6238, ensuring the highest level of security.

## Installation

### Using pip

You can easily install Py2fa via `pip`, Python's package manager. Simply run the following command:

```bash
pip install py2fa
```

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/AxZeRxD/Py2fa.git
   cd Py2fa
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) You can now manually run the tests or use the tool in your project.

## Usage

### Importing Py2fa

To get started, you first need to import the `Totp` class from the package:

```python
from py2fa import Totp
```

### Example Usage

```python
# Example of generating and verifying OTP
secret = "khxi okcj zqtc j54b 2t2x awcr xx3x g5ln"  # Secret key used for TOTP generation

# Initialize the TOTP object for SHA-1 algorithm
pyauth_sha1 = Totp.gen(secret=secret, algorithm="SHA1", digits=6, interval=30)

# Generate OTP
otp_sha1 = pyauth_sha1.genotp()
print(f"Generated OTP (SHA1): {otp_sha1}")

# Verify OTP
if pyauth_sha1.verifyotp(otp_sha1):
    print(f"OTP (SHA1) is valid.")
else:
    print(f"OTP (SHA1) is invalid.")
```

### Supported Algorithms

- **SHA-1**: Default algorithm for TOTP generation.
- **SHA-256**: A more secure option with a longer hash length.
- **SHA-512**: Provides even higher security and longer hash length.

You can switch between these algorithms using the `algorithm` parameter when creating a TOTP instance.

### Configuration

You can configure various aspects of the OTP generation:

- **`digits`**: Number of digits in the OTP (default is 6).
- **`interval`**: The time window for OTP validity in seconds (default is 30 seconds).
- **`algorithm`**: The hashing algorithm to use for OTP generation (options: "SHA1", "SHA256", "SHA512").

## Example for Customization

```python
# Custom configuration for SHA-256 with a 8-digit OTP and 60-second interval
pyauth_sha256 = Totp.gen(secret=secret, algorithm="SHA256", digits=8, interval=60)
otp_sha256 = pyauth_sha256.genotp()
print(f"Generated OTP (SHA256): {otp_sha256}")
```

## Testing

You can run tests to ensure that everything works as expected. If you're using pytest or another test runner, you can run:

```bash
python pytest
```

Or simply run your Python script to check if TOTP generation and verification are working properly.

## Contributing

We welcome contributions! If you have suggestions for improvements, please fork the repository and create a pull request.

1. Fork the repository.
2. Create a new branch for your changes.
3. Commit your changes.
4. Push your changes to your fork.
5. Submit a pull request to the main repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The TOTP implementation follows the RFC 6238 standard for time-based one-time passwords.
- This project was inspired by various TOTP libraries available in the Python ecosystem.
- Thanks to the open-source community for their valuable contributions!

---

- [Discord](https://discord.gg/programmer)
- [Youtube](https://youtube.com/@nukersop)
- [Github](https://github.com/AxZeRxD)

> For any additional questions or support, feel free to open an issue in the repository.
