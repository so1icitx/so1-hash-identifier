

# so1's Hash Identifier

A lightweight Python tool that identifies the type of a given hash string. No external dependencies are required!

## Overview

This project takes a hash string as input and checks it against a built-in database of common hash formats (e.g., MD5, SHA-1, SHA-256, etc.). It then outputs the most likely hash types, helping you quickly determine the hash algorithm used.

## Features

- **No Dependencies:** Runs with Python 3 out-of-the-box.
- **Interactive Mode:** Enter a hash string directly to get results.
- **Command-Line Interface:** Provide a hash as an argument when running the script.
- **Wide Coverage:** Includes many common hash formats (CRC, MD5 variants, SHA variants, and more).

## Installation

Clone the repository:

```sh
git clone https://github.com/so1icitx/so1-hash-identifier.git
cd so1-hash-identifier
```

## Usage

### Run Directly with a Hash String

```sh
python hash_identifier.py "5d41402abc4b2a76b9719d911017c592"
```

### Interactive Mode

Simply run the script without arguments:

```sh
python hash_identifier.py
```

Then enter your hash string when prompted. Type `exit` to quit.





