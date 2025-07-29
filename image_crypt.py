import os
import numpy as np
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
from threading import Thread

class ImageCryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureImage Crypt Pro")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._configure_styles()
        
        # Variables
        self.image_path = ""
        self.original_image = None
        self.processed_image = None
        self.key = ""
        self.processing = False
        self.encryption_method = tk.StringVar(value="AES")
        self.operation_mode = tk.StringVar(value="Encrypt")  # Encrypt/Decrypt
        
        # Create UI
        self.create_widgets()
        
    def _configure_styles(self):
        """Configure custom styles for the application"""
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        self.style.configure('TButton', font=('Helvetica', 10), padding=6)
        self.style.configure('TEntry', font=('Helvetica', 10), padding=5)
        self.style.configure('Header.TLabel', 
                           font=('Helvetica', 16, 'bold'), 
                           foreground='#2c3e50',
                           background='#f0f0f0')
        self.style.configure('Method.TRadiobutton', 
                           font=('Helvetica', 10),
                           background='#f0f0f0')
        self.style.configure('Mode.TRadiobutton', 
                           font=('Helvetica', 10, 'bold'),
                           background='#f0f0f0')
        self.style.configure('ImageFrame.TLabelframe', 
                           background='#ffffff',
                           borderwidth=2,
                           relief=tk.RAISED)
        self.style.configure('Status.TLabel', 
                           background='#2c3e50',
                           foreground='white',
                           font=('Helvetica', 10))
        self.style.configure('Key.TEntry', 
                           font=('Courier New', 10))
        
    def create_widgets(self):
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="15")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(self.header_frame, 
                 text="SecureImage Crypt Pro", 
                 style='Header.TLabel').pack(side=tk.LEFT)
        
        # Operation Mode Toggle
        self.mode_frame = ttk.Frame(self.header_frame)
        self.mode_frame.pack(side=tk.RIGHT)
        
        ttk.Radiobutton(self.mode_frame, 
                       text="Encrypt", 
                       variable=self.operation_mode, 
                       value="Encrypt",
                       style='Mode.TRadiobutton').pack(side=tk.LEFT, padx=5)
        
        ttk.Radiobutton(self.mode_frame, 
                       text="Decrypt", 
                       variable=self.operation_mode, 
                       value="Decrypt",
                       style='Mode.TRadiobutton').pack(side=tk.LEFT, padx=5)
        
        # Image Display Frame
        self.image_frame = ttk.Frame(self.main_frame)
        self.image_frame.pack(fill=tk.BOTH, expand=True)
        
        # Original Image Panel
        self.original_panel = ttk.LabelFrame(self.image_frame, 
                                           text=" Original Image ",
                                           style='ImageFrame.TLabelframe',
                                           padding=10)
        self.original_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.original_canvas = tk.Canvas(self.original_panel, 
                                       bg='#ffffff', 
                                       bd=0, 
                                       highlightthickness=0)
        self.original_canvas.pack(fill=tk.BOTH, expand=True)
        self.original_placeholder = ttk.Label(self.original_panel, 
                                            text="No image loaded\n\nClick 'Open Image'",
                                            foreground='#7f8c8d',
                                            justify=tk.CENTER)
        self.original_placeholder.pack(fill=tk.BOTH, expand=True)
        
        # Processed Image Panel
        self.processed_panel = ttk.LabelFrame(self.image_frame, 
                                            text=" Processed Image ",
                                            style='ImageFrame.TLabelframe',
                                            padding=10)
        self.processed_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.processed_canvas = tk.Canvas(self.processed_panel, 
                                        bg='#ffffff', 
                                        bd=0, 
                                        highlightthickness=0)
        self.processed_canvas.pack(fill=tk.BOTH, expand=True)
        self.processed_placeholder = ttk.Label(self.processed_panel, 
                                             text="Processed image will appear here",
                                             foreground='#7f8c8d',
                                             justify=tk.CENTER)
        self.processed_placeholder.pack(fill=tk.BOTH, expand=True)
        
        # Control Frame
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Encryption Settings Frame
        self.settings_frame = ttk.LabelFrame(self.control_frame, 
                                           text=" Cryptography Settings ",
                                           padding=10)
        self.settings_frame.pack(fill=tk.X, pady=5)
        
        # Method Selection
        ttk.Label(self.settings_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.method_aes = ttk.Radiobutton(self.settings_frame, 
                                        text="AES (Strongest)", 
                                        variable=self.encryption_method, 
                                        value="AES",
                                        style='Method.TRadiobutton')
        self.method_aes.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.method_xor = ttk.Radiobutton(self.settings_frame, 
                                        text="XOR (Fast)", 
                                        variable=self.encryption_method, 
                                        value="XOR",
                                        style='Method.TRadiobutton')
        self.method_xor.grid(row=0, column=2, sticky=tk.W, padx=5)
        
        self.method_chaotic = ttk.Radiobutton(self.settings_frame, 
                                            text="Chaotic (Secure)", 
                                            variable=self.encryption_method, 
                                            value="Chaotic",
                                            style='Method.TRadiobutton')
        self.method_chaotic.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Key Management
        self.key_frame = ttk.Frame(self.control_frame)
        self.key_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(self.key_frame, text="Secret Key:").pack(side=tk.LEFT)
        self.key_entry = ttk.Entry(self.key_frame, show="•", width=60, style='Key.TEntry')
        self.key_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        
        self.show_key = tk.IntVar()
        ttk.Checkbutton(self.key_frame, 
                       text="Show Key", 
                       variable=self.show_key, 
                       command=self.toggle_key_visibility).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(self.key_frame, 
                  text="Generate Key", 
                  command=self.generate_key).pack(side=tk.LEFT)
        
        # Action Buttons
        self.button_frame = ttk.Frame(self.control_frame)
        self.button_frame.pack(fill=tk.X, pady=10)
        
        button_style = {'side': tk.LEFT, 'padx': 5, 'pady': 2, 'ipadx': 10, 'ipady': 5}
        
        ttk.Button(self.button_frame, 
                  text="Open Image", 
                  command=self.open_image).pack(**button_style)
        
        self.process_button = ttk.Button(self.button_frame, 
                                       text="Process Image", 
                                       command=self.process_image)
        self.process_button.pack(**button_style)
        
        ttk.Button(self.button_frame, 
                  text="Save Result", 
                  command=self.save_image).pack(**button_style)
        
        ttk.Button(self.button_frame, 
                  text="Reset", 
                  command=self.reset).pack(**button_style)
        
        # Status Bar
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.status_frame, 
                                  textvariable=self.status_var, 
                                  style='Status.TLabel',
                                  anchor=tk.W,
                                  padding=5)
        self.status_bar.pack(fill=tk.X)
        
    def toggle_key_visibility(self):
        if self.show_key.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="•")
    
    def open_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.webp"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            self.image_path = file_path
            self.display_original_image()
    
    def display_original_image(self):
        try:
            self.original_image = Image.open(self.image_path)
            self.update_image_display(self.original_image, self.original_canvas, self.original_placeholder)
            self.status_var.set(f"Loaded: {os.path.basename(self.image_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
            self.status_var.set("Error loading image")
    
    def update_image_display(self, image, canvas, placeholder):
        placeholder.pack_forget()
        
        # Calculate available space
        canvas_width = canvas.winfo_width()
        canvas_height = canvas.winfo_height()
        
        if canvas_width <= 1 or canvas_height <= 1:
            return
            
        # Create thumbnail that fits in the canvas
        img = image.copy()
        img.thumbnail((canvas_width - 20, canvas_height - 20))
        
        # Center the image
        x = (canvas_width - img.width) // 2
        y = (canvas_height - img.height) // 2
        
        # Update display
        photo = ImageTk.PhotoImage(img)
        canvas.image = photo  # Keep reference
        canvas.delete("all")
        canvas.create_image(x, y, anchor=tk.NW, image=photo)
        
        # Bind canvas resize
        canvas.bind("<Configure>", lambda e: self.on_canvas_resize(e, image, canvas))
    
    def on_canvas_resize(self, event, image, canvas):
        if image and canvas:
            self.update_image_display(image, canvas, 
                                   self.original_placeholder if canvas == self.original_canvas 
                                   else self.processed_placeholder)
    
    def generate_key(self):
        key = base64.b64encode(os.urandom(32)).decode('utf-8')
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        self.status_var.set("Generated new encryption key")
    
    def process_image(self):
        if not self.image_path:
            messagebox.showwarning("Warning", "Please open an image first")
            return
            
        self.key = self.key_entry.get()
        if not self.key:
            messagebox.showwarning("Warning", "Please enter a secret key")
            return
            
        self.processing = True
        operation = self.operation_mode.get()
        method = self.encryption_method.get()
        self.status_var.set(f"{operation}ing image using {method}...")
        
        # Update button text
        self.process_button.config(text=f"{operation}ing...")
        
        # Disable buttons during processing
        for child in self.button_frame.winfo_children():
            child.configure(state=tk.DISABLED)
        
        # Process in a separate thread to keep UI responsive
        Thread(target=self._process_image, daemon=True).start()
    
    def _process_image(self):
        try:
            img = Image.open(self.image_path)
            img_array = np.array(img)
            
            method = self.encryption_method.get()
            operation = self.operation_mode.get()
            
            if operation == "Encrypt":
                if method == "AES":
                    self.processed_image = self._aes_encrypt(img_array)
                elif method == "XOR":
                    self.processed_image = self._xor_encrypt(img_array)
                elif method == "Chaotic":
                    self.processed_image = self._chaotic_encrypt(img_array)
            else:  # Decrypt
                if method == "AES":
                    self.processed_image = self._aes_decrypt(img_array)
                elif method == "XOR":
                    self.processed_image = self._xor_decrypt(img_array)
                elif method == "Chaotic":
                    self.processed_image = self._chaotic_decrypt(img_array)
            
            self.root.after(0, self._process_complete)
            
        except Exception as e:
            self.root.after(0, lambda: self._process_error(f"{self.operation_mode.get()}ion failed: {str(e)}"))
    
    # AES Encryption/Decryption
    def _aes_encrypt(self, img_array):
        """Encrypt using AES in CBC mode"""
        # Generate key and IV from the user key
        key = hashlib.sha256(self.key.encode()).digest()
        iv = hashlib.md5(self.key.encode()).digest()[:16]
        
        # Store original shape and flatten
        original_shape = img_array.shape
        flat_array = img_array.flatten()
        
        # Pad the data to be multiple of 16 bytes (AES block size)
        pad_len = (16 - (len(flat_array) % 16)) % 16
        padded_data = np.append(flat_array, np.zeros(pad_len, dtype=np.uint8))
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data.tobytes()) + encryptor.finalize()
        
        # Reshape back to image dimensions (without padding)
        encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
        encrypted_array = encrypted_array[:len(flat_array)].reshape(original_shape)
        
        return Image.fromarray(encrypted_array)
    
    def _aes_decrypt(self, img_array):
        """Decrypt using AES in CBC mode"""
        # Generate same key and IV used for encryption
        key = hashlib.sha256(self.key.encode()).digest()
        iv = hashlib.md5(self.key.encode()).digest()[:16]
        
        # Store original shape and flatten
        original_shape = img_array.shape
        flat_array = img_array.flatten()
        
        # Pad the data to be multiple of 16 bytes
        pad_len = (16 - (len(flat_array) % 16)) % 16
        padded_data = np.append(flat_array, np.zeros(pad_len, dtype=np.uint8))
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(padded_data.tobytes()) + decryptor.finalize()
        
        # Reshape back to image dimensions (without padding)
        decrypted_array = np.frombuffer(decrypted_data, dtype=np.uint8)
        decrypted_array = decrypted_array[:len(flat_array)].reshape(original_shape)
        
        return Image.fromarray(decrypted_array)
    
    # XOR Encryption/Decryption
    def _xor_encrypt(self, img_array):
        """Encrypt using XOR with key-derived sequence"""
        # Generate deterministic sequence from key
        key_hash = hashlib.sha256(self.key.encode()).digest()
        key_sequence = np.frombuffer(key_hash * (img_array.size // len(key_hash) + 1), dtype=np.uint8)
        key_sequence = key_sequence[:img_array.size].reshape(img_array.shape)
        
        # Perform XOR encryption
        encrypted_array = np.bitwise_xor(img_array, key_sequence)
        
        return Image.fromarray(encrypted_array)
    
    def _xor_decrypt(self, img_array):
        """Decrypt using XOR (same as encryption)"""
        return self._xor_encrypt(img_array)  # XOR is symmetric
    
    # Chaotic Encryption/Decryption
    def _chaotic_encrypt(self, img_array):
        """Encrypt using chaotic logistic map"""
        # Parameters for chaotic map
        r = 3.9
        
        # Generate chaotic sequence from key
        key_hash = hashlib.sha256(self.key.encode()).digest()
        x = sum(byte / 256 for byte in key_hash) / len(key_hash)
        
        height, width = img_array.shape[0], img_array.shape[1]
        chaotic_sequence = np.zeros(img_array.size, dtype=np.float64)
        
        for i in range(img_array.size):
            x = r * x * (1 - x)
            chaotic_sequence[i] = x
        
        # Scale to 0-255 and reshape
        chaotic_sequence = (chaotic_sequence * 255).astype(np.uint8)
        chaotic_sequence = chaotic_sequence.reshape(img_array.shape)
        
        # Perform encryption
        encrypted_array = (img_array + chaotic_sequence) % 256
        
        return Image.fromarray(encrypted_array)
    
    def _chaotic_decrypt(self, img_array):
        """Decrypt using chaotic logistic map"""
        # Parameters for chaotic map
        r = 3.9
        
        # Generate same chaotic sequence from key
        key_hash = hashlib.sha256(self.key.encode()).digest()
        x = sum(byte / 256 for byte in key_hash) / len(key_hash)
        
        height, width = img_array.shape[0], img_array.shape[1]
        chaotic_sequence = np.zeros(img_array.size, dtype=np.float64)
        
        for i in range(img_array.size):
            x = r * x * (1 - x)
            chaotic_sequence[i] = x
        
        # Scale to 0-255 and reshape
        chaotic_sequence = (chaotic_sequence * 255).astype(np.uint8)
        chaotic_sequence = chaotic_sequence.reshape(img_array.shape)
        
        # Perform decryption
        decrypted_array = (img_array - chaotic_sequence) % 256
        
        return Image.fromarray(decrypted_array)
    
    def _process_complete(self):
        self.display_processed_image()
        self.processing = False
        operation = self.operation_mode.get()
        method = self.encryption_method.get()
        self.status_var.set(f"{operation}ion complete using {method}!")
        
        # Restore button text
        self.process_button.config(text="Process Image")
        
        # Re-enable buttons
        for child in self.button_frame.winfo_children():
            child.configure(state=tk.NORMAL)
    
    def _process_error(self, message):
        messagebox.showerror("Error", message)
        self.status_var.set("Ready")
        self.processing = False
        
        # Restore button text
        self.process_button.config(text="Process Image")
        
        # Re-enable buttons
        for child in self.button_frame.winfo_children():
            child.configure(state=tk.NORMAL)
    
    def display_processed_image(self):
        if self.processed_image:
            self.update_image_display(self.processed_image, self.processed_canvas, self.processed_placeholder)
    
    def save_image(self):
        if not self.processed_image or self.processing:
            messagebox.showwarning("Warning", "No processed image to save")
            return
            
        default_ext = ".png" if self.operation_mode.get() == "Encrypt" else ".png"
        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=[
                ("PNG", "*.png"),
                ("JPEG", "*.jpg"),
                ("WebP", "*.webp"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            try:
                self.processed_image.save(file_path)
                self.status_var.set(f"Image saved to: {os.path.basename(file_path)}")
                messagebox.showinfo("Success", "Image saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save image: {str(e)}")
    
    def reset(self):
        if self.processing:
            return
            
        self.image_path = ""
        self.original_image = None
        self.processed_image = None
        self.key_entry.delete(0, tk.END)
        
        # Clear canvases
        self.original_canvas.delete("all")
        self.processed_canvas.delete("all")
        
        # Restore placeholders
        self.original_placeholder.pack(fill=tk.BOTH, expand=True)
        self.processed_placeholder.pack(fill=tk.BOTH, expand=True)
        
        self.status_var.set("Ready")

if __name__ == "__main__":
    root = tk.Tk()
    
    # Set window icon (optional)
    try:
        root.iconbitmap(default='icon.ico')  # Provide an icon file if available
    except:
        pass
        
    app = ImageCryptApp(root)
    
    # Make the app responsive
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    root.mainloop()