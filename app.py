# Import required libraries
import streamlit as st
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from PIL import Image
import os
import json
from datetime import datetime
from io import BytesIO

# Size of salt for cryptographic operations
SALT_SIZE = 16  # Can be adjusted according to needed length

class Steganography:
    """
    This class provides methods for hiding and extracting binary data within an image using LSB steganography.
    """
    @staticmethod
    def calculate_image_hash(image):
        """
        Calculates the SHA-256 hash of an image excluding the least significant bit of each pixel channel.

        Args:
            image: PIL.Image object - The original image to calculate the hash for.

        Returns:
            image_hash: bytes - The SHA-256 hash of the image.
        """
        image_data = list(image.getdata())
        significant_bits_data = [(channel & ~1 for channel in pixel) for pixel in image_data]
        flattened_data = [bit for pixel in significant_bits_data for bit in pixel]
        data_bytes = bytes(flattened_data)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(data_bytes)
        image_hash = hasher.finalize()
        return image_hash
    
    @staticmethod
    def embed_data(image, data):
        """
        Embeds binary data into an image using LSB steganography.

        Args:
            image: PIL.Image object - The original image to hide data in.
            data: bytes - The binary data to hide.

        Returns:
            modified_image: PIL.Image object - The image with embedded data.
        """
        binary_data = ''.join(format(byte, '08b') for byte in data)
        image_data = list(image.getdata())
        modified_image_data = []

        for i, pixel in enumerate(image_data):
            if i < len(binary_data):
                modified_pixel = tuple((channel & ~1) | int(binary_data[i]) for channel in pixel)
                modified_image_data.append(modified_pixel)
            else:
                modified_image_data.append(pixel)

        modified_image = Image.new(image.mode, image.size)
        modified_image.putdata(modified_image_data)
        return modified_image

    @staticmethod
    def extract_data(image, data_length):
        """
        Extracts embedded binary data from an image.

        Args:
            image: PIL.Image object - The image with embedded data.
            data_length: int - The length of the data to extract.

        Returns:
            extracted_data: bytearray - The extracted data.
        """
        image_data = list(image.getdata())
        binary_data = ''.join(str(pixel[0] & 1) for pixel in image_data[:data_length * 8])
        extracted_data = bytearray(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))
        return extracted_data


class Cryptography:
    """
    This class encapsulates cryptographic functionalities like signing messages, verifying signatures, 
    and encryption and decryption of messages.
    """
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def sign_message(self, message):
        """
        Signs a given message using the user's private key.

        Args:
            message: bytes - The message to be signed.

        Returns:
            signature: bytes - The signature of the message.
        """
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, message, signature):
        """
        Verifies a given message's signature using the sender's public key.

        Args:
            message: bytes - The original message.
            signature: bytes - The signature of the message to verify.
        """
        try:
            self.public_key.verify(
                bytes(signature),
                bytes(message),
                ec.ECDSA(hashes.SHA256())
            )
            #print("The signature is valid.")
        except InvalidSignature:
            #print("The signature is invalid.")
            st.error("The signature is invalid.")

    @staticmethod
    def generate_salt(length):
        """
        Generates a random salt of a specified length.

        Args:
            length: int - The desired length of the salt.

        Returns:
            salt: bytes - The generated salt.
        """
        return os.urandom(length)

    def generate_shared_key(self, recipient_public_key):
        """
        Generates a shared key using the user's private key and the recipient's public key.

        Args:
            recipient_public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey - 
                                  The public key of the recipient.

        Returns:
            shared_key: bytes - The generated shared key.
        """
        shared_key = self.private_key.exchange(ec.ECDH(), recipient_public_key)
        return shared_key

    def derive_key(self, shared_key, salt):
        """
        Derives a key from the shared key using HKDF and a given salt.

        Args:
            shared_key: bytes - The shared key.
            salt: bytes - The salt for the HKDF operation.

        Returns:
            derived_key: bytes - The derived key.
        """
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key

    def encrypt_message(self, json_data, derived_key):
        """
        Encrypts a given JSON data using the derived key.

        Args:
            json_data: str - The JSON data to encrypt.
            derived_key: bytes - The key to use for encryption.

        Returns:
            ciphertext: bytes - The encrypted message.
        """
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(json_data.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def decrypt_message(self, ciphertext, derived_key):
        """
        Decrypts a given ciphertext using the derived key.

        Args:
            ciphertext: bytes - The ciphertext to decrypt.
            derived_key: bytes - The key to use for decryption.

        Returns:
            json_data_out: bytes - The decrypted message.
        """
        cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
        decryptor = cipher.decryptor()
        padded_data_out = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        json_data_out = unpadder.update(padded_data_out) + unpadder.finalize()
        return json_data_out


class User:
    """
    This class represents a user of the system, holding an instance of the Cryptography class.
    """
    def __init__(self, private_key, public_key):
        self.crypto = Cryptography(private_key, public_key)


# Generate new keys if they don't exist
def generate_and_save_keys(file_path):
    # Generate private and public keys
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    # Serialize the keys
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convert the keys to strings
    private_key_str = private_key_bytes.decode('utf-8')
    public_key_str = public_key_bytes.decode('utf-8')

    # Create a dictionary to store the keys
    keys = {
        'private_key': private_key_str,
        'public_key': public_key_str
    }

    # Save the keys to a JSON file
    with open(file_path, 'w') as f:
        json.dump(keys, f)

# Load keys
def load_keys(user_name):
    file_path = f'keys_{user_name}.json'
    # Check if already file path
    if not os.path.isfile(file_path):
        generate_and_save_keys(file_path)
    
    # Load the keys from the JSON file
    with open(file_path, 'r') as f:
        keys = json.load(f)

    # Convert the keys to bytes
    private_key_pem = keys['private_key'].encode('utf-8')
    public_key_pem = keys['public_key'].encode('utf-8')

    # Load the keys
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    public_key = serialization.load_pem_public_key(
        public_key_pem
    )

    return private_key, public_key


# Load in keys from JSON or generate new ones if they don't exist
private_key_alice, public_key_alice = load_keys('Alice')
private_key_bob, public_key_bob = load_keys('Bob')
private_key_charlie, public_key_charlie = load_keys('Charlie')

# Initialize users
alice = User(private_key_alice, public_key_alice)
bob = User(private_key_bob, public_key_bob)
charlie = User(private_key_charlie, public_key_charlie)

# Create a user dictionary for easy access
users = {"Alice": alice, "Bob": bob, "Charlie": charlie}

def encrypt_page():
    img_file = None
    original_image = None
    image_hash = None
    
    st.title("Hidden in Plain Byte - Encryption Page")
    
    st.markdown("""
    **Instructions** - 
    This page allows you to write a message and embed it in an image. 
    1. Here you are the `Sender`, you may select any of the three (Alice, Bob, or Charlie) and you must also choose a `reciever` (The same three. You can also send it to yourself)
    2. Upload an image or take a picture via the camera.
    3. Write a secret message (Once you encrypt it, only the recipient will be able to decrypt it.)
    4. Click `Encrypt and Embed Message`
    5. Once the image has finished loading, click `Download image`
    """)

    sender_name = st.selectbox("Select the sender", ["Alice", "Bob", "Charlie"])
    recipient_name = st.selectbox("Select the recipient", ["Alice", "Bob", "Charlie"], index=1)
    sender = users[sender_name]
    recipient = users[recipient_name]
        
    source_selection = st.radio("Choose your image source", ('Upload', 'Camera'))

    img_file = None
    original_image = None
    image_hash = None

    if source_selection == 'Upload':
        img_file = st.file_uploader("Upload an image for steganography", type=['png'])
        # get the hash of the non-lsb image bytes
        if img_file:
            original_image = Image.open(img_file)
            image_hash = Steganography.calculate_image_hash(original_image)
            image_origin = f"{sender_name}'s photo library"

    elif source_selection == 'Camera':
        img_file = st.camera_input(disabled=False, label="camera")
        # get the hash of the non-lsb image bytes
        if img_file:
            original_image = Image.open(img_file)
            image_hash = Steganography.calculate_image_hash(original_image)
            image_origin = "In-app Camera"
        
    message = st.text_input("Enter your message here:")
    encrypt_btn = st.button("Encrypt and Embed Message")

    if encrypt_btn and img_file and message and image_hash != None:

        # Prepare the data to be sent
        data = {
            "message": message,
            "timestamp": str(datetime.now()),
            "nonce": os.urandom(16).hex(),
            "image_hash": image_hash.hex()
        }
        json_data = json.dumps(data)

        # Generate salt and shared key
        salt = sender.crypto.generate_salt(SALT_SIZE)
        shared_key_sender = sender.crypto.generate_shared_key(recipient.crypto.public_key)

        # Derive the key using the salt and shared key
        derived_key = sender.crypto.derive_key(shared_key_sender, salt)
        ciphertext = sender.crypto.encrypt_message(json_data, derived_key)
        signature = sender.crypto.sign_message(ciphertext)

        # Combine lengths, salt, encrypted message, and signature
        message_length_bytes = len(ciphertext).to_bytes(4, 'big')
        signature_length_bytes = len(signature).to_bytes(4, 'big')
        salt_length_bytes = len(salt).to_bytes(4, 'big')
        combined_data = message_length_bytes + signature_length_bytes + salt_length_bytes + salt + ciphertext + signature

        # Embed the data into an image and save the modified image
        modified_image = Steganography.embed_data(original_image, combined_data)
        modified_image.save("output.png")
        st.success("Message encrypted and embedded into image successfully!")
        
        st.image(modified_image, caption='Modified Image Thumbnail', width=150)
        with open("output.png", "rb") as file:
            btn = st.download_button(
                    label="Download image",
                    data=file,
                    file_name="output.png",
                    mime="image/png"
                  )

def decrypt_page():
    img_file = None
    decrypt_btn = None
    st.title("Hidden in Plain Byte - Decryption Page")
    
    st.markdown("""
    **Instructions** - 
    This page allows you to extract and decrypt a message from an image. 
    1. Here you are the `Receiver`. To successully read the message you must make sure that you select the same `sender` and `recipient` chosen during encryption in order to verify the sender and to make sure that the message is safely going to the correct recipient.
    2. Upload the image with the embeded message (the image you downloaded on the encryption page)
    3. Click `Decrypt Message from Image`
    4. If the signature and image hash verfications are successful, the decrypted messaged will be revealed.
    """)

    sender_name = st.selectbox("Select the sender", ["Alice", "Bob", "Charlie"])
    recipient_name = st.selectbox("Select the recipient", ["Alice", "Bob", "Charlie"], index=1)
    recipient = users[recipient_name]
    sender = users[sender_name]


    img_file = st.file_uploader("Upload an encrypted image for extraction", type=['png'])
    if img_file != None:
        modified_image = Image.open(img_file)
    decrypt_btn = st.button("Decrypt Message from Image")

    if decrypt_btn and img_file:

        # Extract the data from the modified image
        header = Steganography.extract_data(Image.open(img_file), 12)  # Increased from 8 to 12 to account for the salt length
        message_length = int.from_bytes(header[:4], 'big')
        signature_length = int.from_bytes(header[4:8], 'big')
        salt_length = int.from_bytes(header[8:], 'big')

        extracted_data = Steganography.extract_data(Image.open(img_file), 12 + message_length + signature_length + salt_length)
        salt_out = bytes(extracted_data[12:12+salt_length])
        ciphertext_out = bytes(extracted_data[12+salt_length:12+salt_length+message_length])
        signature_out = bytes(extracted_data[12+salt_length+message_length:12+salt_length+message_length+signature_length])

        sender.crypto.verify_signature(ciphertext_out, signature_out)

        # Recipient generates shared key and derives key using the extracted salt
        shared_key_recipient = recipient.crypto.generate_shared_key(sender.crypto.public_key)
        derived_key = recipient.crypto.derive_key(shared_key_recipient, salt_out)
        json_data_out = recipient.crypto.decrypt_message(ciphertext_out, derived_key)
        data_out = json.loads(json_data_out.decode())
        
        image_hash_out = bytes.fromhex(data_out["image_hash"])
    
        # Verify Image Hash
        hash_verification_image = Steganography.calculate_image_hash(modified_image)
        if hash_verification_image != image_hash_out:
            #print("Image verification failed!")
            st.error("Image verification failed!")
        else:
            #print("Image and Signature verification successful!")
            st.success("Image and Signature verification successful!")
            
        
        #print(data_out)

        st.text("Decrypted Message:")
        st.info(data_out['message'])
        
def home_page():
    st.title("Hidden in Plain Byte")
    
    st.header("`P2P Encrypted Steganogaphy`")
    
    st.image("header-image.png")
    
    st.markdown(
    """
    This demo explores a potential method of secure communication which encrypts private messages and hides them within digital images using LSB steganography. It leverages Public Key Cryptography, ECDH Key Exchange, HKDF, Image Hashing, Digital Signature, and Padding to ensure the confidentiality, integrity, and authenticity of the hidden messages. This blend of cryptography and steganography provides a robust approach to protect data against unauthorized access while simultaneously hidden in plain sight.
    """)

    st.markdown("""
    ### Key Features:

    #### Public Key Cryptography:
    Each user (Alice, Bob, and Charlie) has a pair of private and public keys. These keys are used for two purposes:
    - **Signing messages:** The sender uses their private key to sign the encrypted message. This signature can be verified by the recipient using the sender's public key to ensure that the message was sent by the claimed sender.
    - **Encrypting messages:** A shared secret key is derived using the sender's private key and the recipient's public key. This key is used to encrypt and decrypt the message.

    #### Elliptic-Curve Diffie-Hellman (ECDH) Key Exchange:
    The shared secret key is generated using ECDH key exchange, which ensures that even if an attacker knows the public keys of both the sender and recipient, they can't derive the shared key.

    #### Hash-based Key Derivation Function (HKDF):
    HKDF is used to derive the encryption key from the shared secret key. A random salt is generated for each message to ensure that the derived key is unique even if the shared key and the message are the same.

    #### Hashing:
    The SHA-256 hash of the original image (excluding the least significant bit of each pixel channel) is calculated and included in the message. This allows the recipient to verify that the image hasn't been modified after the data was embedded.

    #### Digital Signature:
    The sender signs the encrypted message using their private key. This allows the recipient to verify the authenticity of the sender and the integrity of the message.

    #### Least Significant Bit (LSB) Steganography:
    The encrypted message, the signature, and some metadata (like the lengths of the message, the signature, and the salt, and the salt itself) are embedded into the image using LSB steganography. This technique hides the data within the least significant bits of the pixel data, making it almost indistinguishable from the original image.

    #### Padding:
    Padding is added to the JSON data before encryption to ensure that the length of the data is a multiple of the block size of the cipher (AES in this case). The padding is removed after decryption.

    """)

    st.markdown("![Alt Text](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExOWU4ZGVlNjIxNjE0OTk1NGFiNWNjZmUzM2ZiYTljY2IzYTFlOTQyOSZlcD12MV9pbnRlcm5hbF9naWZzX2dpZklkJmN0PWc/xFyxZjsX4ItgERKObC/giphy.gif)")

    
    st.markdown("""
## How it Works

## Encryption Page

When the sender wants to send a private message, they:

- Choose an image to use as a carrier for the message.
- The image’s bits excluding the least significant bits are hashed with SHA-256 and added to the data to be embedded into the image.
- The Sender then enters a the message to be sent.
- The system then encrypts this message, along with the other data to be embedded, using a derived key. The derived key is a combination of a shared key and a randomly generated salt. The shared key is generated using the sender's private key and the recipient's public key.
- The sender then signs the encrypted data using their private key. This signature will be used by the recipient to verify the authenticity of the message.
- The encrypted data, along with the salt and the sender's signature, is then embedded into the image using LSB (Least Significant Bit) steganography. This method of steganography alters the least significant bits of the image's pixel data to store the encrypted message, making the changes virtually indistinguishable to the human eye.
- Once embedded, a modified image is created with a download button.

""")
    
    st.image("diagram-1.png")
    
    st.markdown("""
## Decryption Page
Upon receiving the image, the recipient:

- Selects the received modified image for decryption.
- The system then extracts the embedded data from the image. This includes the encrypted data, the salt, and the sender's signature.
- The recipient's system verifies the sender's signature using the sender's public key. If the signature is valid, it confirms that the data is indeed from the sender and hasn't been tampered with during transmission.
- The system then decrypts the data using a key derived from the shared key and the extracted salt. The shared key is generated using the recipient's private key and the sender's public key.
- A hash is then taken of the bits of the modified image excluding the least significant bits and is compared with the hash that was embedded in the encrypted data. If both hashes match, then the recipient can verify that the image was not tampered with during transit.
- Finally, the original plaintext message is displayed to the recipient.

This way, the system ensures secure communication between parties, with messages being confidential (only the intended recipient can decrypt and read the message) and authentic (the recipient can verify the sender of the message).

## Potential Weaknesses of this Demo

While this application uses robust cryptographic techniques, it does have potential weaknesses:

* **Electronic Code Book (ECB):** ECB is one of the simplest and weakest types of encryption methods, but this can be easily substituted with a more advanced method of AES.

* **Encryption Key Security:** If the shared secret key from the ECC-based Diffie-Hellman exchange is compromised, an attacker could decrypt the hidden messages.
  
* **Image Transmission:** The image must be transmitted without any form of lossy compression (such as JPEG compression), which could remove or alter the hidden data, so for the time being this demo is focused on `.png` images.
  
* **Limited Message Size:** The length of the hidden message is limited by the size of the image. Large messages may require larger images.

* **Digital Signature Compromise:** If the sender's private key is compromised, an attacker could forge digital signatures.

* **Steganography Technique:** LSB Steganography is one of the less advanced forms of Steganography, there are some forms that may be better suited for this type of application.

* **RGB Channel:** While the Image hash function creates a hash of the image bits, excluding the least significant bits, of all three color channels Red, Green, and Blue, the encrypted data was only embedded in the Red Channel for this demo; however, this is a minor change that could allow for larger embedded files, which wasn't necessary for this demo. 

## Contact:
- Author: **Preston Kirschner**
- Socials: [LinkedIn](https://www.linkedin.com/in/preston-kirschner/) | [Github](https://github.com/P-carth) | [Twitter](https://twitter.com/Prestonk_)
- I would love to hear your feedback (positive or negative)! Please reach out on one of the socials above if you have questions or comments.
""")

    



def main():
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.selectbox("Choose the task", ["Home Page","Encryption Page", "Decryption Page"])

    
    if app_mode == "Home Page":
        home_page()
    if app_mode == "Encryption Page":
        encrypt_page()
    elif app_mode == "Decryption Page":
        decrypt_page()

if __name__ == "__main__":
    main()
