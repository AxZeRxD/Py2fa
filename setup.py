from setuptools import setup, find_packages

setup(
    name="your_package_name", 
    version="0.1.0",  
    packages=find_packages(),  
    install_requires=[
        "uwulogger",
        "colorama",
    ],
    author="Aizer",
    author_email="mohit.4sure@gmail.com",  
    description="A simple TOTP generator package to help you in developing tools that require TOTP", 
    long_description=open("README.md").read(),  
    long_description_content_type="text/markdown", 
    url="https://github.com/yourusername/your-repository", 
    classifiers=[ 
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.6", 
)
