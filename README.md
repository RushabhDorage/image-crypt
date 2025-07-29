# image-crypt
image-crypt is a cross-platform image encryption tool with a beautiful modern UI built using Python and Tkinter. It supports AES (CBC), XOR-based, and chaotic encryption algorithms, allowing users to visually and securely encrypt or decrypt images. With built-in key generation, real-time previews, and multiple save formats .




# 🖼️🔐 Image Crypt

A desktop GUI tool for encrypting and decrypting images using multiple cryptographic techniques — AES, XOR, and chaotic logistic maps. Built using Python and Tkinter, this app features a polished, responsive interface, live previews, and customizable secret key management.



 ✨ Features

- 🔒 AES (CBC mode)for strong encryption
- ⚡ XOR mode for quick and lightweight protection
- 🧬 Chaotic Map Encryption using a logistic function for secure obfuscation
- 🧠 Smart key management and base64 random key generation
- 🎨 Live preview of original and processed images
- 🧰 Save results in PNG, JPEG, WebP, and more
- 🖥️ Clean, intuitive GUI with Tkinter
- 📦 No server or internet required — runs locally


🛠️ Installation

📌 Prerequisites

- Python 3.8+
- pip

🧪 Dependencies

Install required packages:

pip install -r requirements.txt


Or manually:

pip install pillow cryptography numpy


 🚀 Running the App

python image_crypt.py




 🧠 Encryption Modes

| Mode    | Type      | Notes                                               |
| ------- | --------- | --------------------------------------------------- |
| AES     | Symmetric | Uses CBC mode with SHA-256 key + MD5 IV             |
| XOR     | Symmetric | Fast, reversible with same key                      |
| Chaotic | Nonlinear | Uses logistic map function for key-based randomness |


🔐 Secret Key System

* You can enter a custom key or click "Generate Key" for a 256-bit random base64 key.
* Key visibility toggle ensures safety and ease of use.



💾 Supported Formats

* Open: PNG, JPEG, BMP, WebP
* Save: PNG, JPEG, WebP


 🧑‍💻 Use Cases

* Steganography / Data hiding
* Educational cryptography projects
* Image security demos
* Fun with chaos-based encryption



📜 License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for more details.


🙌 Credits

* [Pillow](https://python-pillow.org/)
* [Cryptography](https://cryptography.io/)
* [NumPy](https://numpy.org/)

  
 Inspired by the intersection of visual computing and data privacy

🛡️ Disclaimer

This tool is for **educational and research purposes only**. It does not replace professional cryptographic software for production use.





LICENSE

MIT License

Copyright (c) 2025 [Rushabh Dorage]


