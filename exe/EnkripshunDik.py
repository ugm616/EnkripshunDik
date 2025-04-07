#!/usr/bin/env python3
"""
Portable Image Encryption Tool
Based on steganographic LSB encryption with visual scrambling
"""

import os
import json
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
from typing import Tuple, Dict, Any, Optional
import secrets
import array

class ImageEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        self.root.configure(bg="#2c2c2c")

        # Set dark theme
        style = ttk.Style()
        style.theme_use('alt')
        style.configure('TFrame', background='#2c2c2c')
        style.configure('TButton', background='#444', foreground='white', 
                        font=('Arial', 10), borderwidth=1, relief='raised')
        style.map('TButton', 
                  background=[('active', '#555')],
                  relief=[('pressed', 'sunken')])
        style.configure('TLabel', background='#2c2c2c', foreground='white', font=('Arial', 10))
        style.configure('TRadiobutton', background='#2c2c2c', foreground='white', font=('Arial', 10))
        
        # Global variables
        self.original_image = None
        self.encrypted_image = None
        self.password_file_path = None
        self.password_hash = None

        # Main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create left panel (input image)
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Image input area
        ttk.Label(left_panel, text="Input Image").pack(pady=(0, 5), anchor='w')
        self.input_preview = tk.Canvas(left_panel, bg="#333333", height=300)
        self.input_preview.pack(fill=tk.BOTH, expand=True)
        self.input_placeholder_text = self.input_preview.create_text(
            150, 150, text="Select an image to encrypt or decrypt...", fill="white")
        
        input_buttons_frame = ttk.Frame(left_panel)
        input_buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(input_buttons_frame, text="Choose Image", 
                   command=self.load_image).pack(side=tk.LEFT, padx=5)
        
        # Password section
        password_frame = ttk.LabelFrame(left_panel, text="Password", padding=(10, 5))
        password_frame.pack(fill=tk.X, pady=10)
        
        # Password mode selection
        self.password_mode = tk.StringVar(value="simple")
        
        ttk.Radiobutton(password_frame, text="Simple Password", value="simple",
                       variable=self.password_mode, 
                       command=self.toggle_password_mode).grid(row=0, column=0, padx=5, sticky='w')
        
        ttk.Radiobutton(password_frame, text="File Password", value="advanced", 
                       variable=self.password_mode,
                       command=self.toggle_password_mode).grid(row=0, column=1, padx=5, sticky='w')
        
        # Simple password input
        self.simple_password_frame = ttk.Frame(password_frame)
        self.simple_password_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky='we')
        
        ttk.Label(self.simple_password_frame, text="Password:").pack(side=tk.LEFT, padx=5)
        self.password_entry = ttk.Entry(self.simple_password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # File password input
        self.advanced_password_frame = ttk.Frame(password_frame)
        self.file_password_label = ttk.Label(self.advanced_password_frame, 
                                           text="Select a file to use as password...")
        self.file_password_label.pack(fill=tk.X, pady=5)
        ttk.Button(self.advanced_password_frame, text="Choose Password File",
                  command=self.choose_password_file).pack(pady=5)
        
        # Initially hide the advanced frame
        # Will be shown/hidden based on radio button selection
        
        # Create right panel (output image)
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_panel, text="Output Image").pack(pady=(0, 5), anchor='w')
        self.output_preview = tk.Canvas(right_panel, bg="#333333", height=300)
        self.output_preview.pack(fill=tk.BOTH, expand=True)
        self.output_placeholder_text = self.output_preview.create_text(
            150, 150, text="Encrypted/Decrypted image will appear here...", fill="white")
        
        output_buttons_frame = ttk.Frame(right_panel)
        output_buttons_frame.pack(fill=tk.X, pady=10)
        
        self.encrypt_btn = ttk.Button(output_buttons_frame, text="Encrypt", 
                                    command=self.encrypt_image)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.decrypt_btn = ttk.Button(output_buttons_frame, text="Decrypt",
                                    command=self.decrypt_image)
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_btn = ttk.Button(output_buttons_frame, text="Save Image", 
                                  command=self.save_image, state=tk.DISABLED)
        self.save_btn.pack(side=tk.RIGHT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("Ready")
        
        # Set initial state
        self.toggle_password_mode()

    def toggle_password_mode(self):
        if self.password_mode.get() == "simple":
            # Show simple password, hide advanced
            self.simple_password_frame.grid()
            if self.advanced_password_frame.winfo_ismapped():
                self.advanced_password_frame.grid_remove()
            self.status_var.set("Simple password mode activated")
        else:
            # Show advanced password, hide simple
            self.advanced_password_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky='we')
            self.simple_password_frame.grid_remove()
            self.status_var.set("File password mode activated")

    def load_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            # Load and display the image
            self.original_image = Image.open(file_path)
            
            # Check if the image is too small
            if self.original_image.width * self.original_image.height < 256:
                messagebox.showerror(
                    "Image Too Small", 
                    "The selected image is too small for encryption.\n"
                    "Please select an image with at least 256 pixels."
                )
                self.original_image = None
                return
            
            self.display_image(self.original_image, self.input_preview, self.input_placeholder_text)
            self.status_var.set(f"Loaded image: {os.path.basename(file_path)}")
            
            # Check if this is an encrypted image
            metadata = self.check_for_steganography()
            if metadata:
                self.status_var.set(f"Loaded encrypted image: {os.path.basename(file_path)}")
                # Set password mode based on detected metadata
                self.password_mode.set("simple" if metadata["mode"] == "simple" else "advanced")
                self.toggle_password_mode()
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
            self.status_var.set("Error loading image")

    def choose_password_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Password File",
            filetypes=[("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            # Generate hash from the file
            self.password_file_path = file_path
            self.password_hash = self.generate_file_hash(file_path)
            filename = os.path.basename(file_path)
            filesize = os.path.getsize(file_path)
            
            # Format size for display
            if filesize < 1024:
                size_str = f"{filesize} bytes"
            elif filesize < 1048576:
                size_str = f"{filesize/1024:.1f} KB"
            else:
                size_str = f"{filesize/1048576:.1f} MB"
                
            self.file_password_label.configure(text=f"File: {filename} ({size_str})")
            self.status_var.set(f"Password file selected: {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process password file: {str(e)}")
            self.status_var.set("Error processing password file")

    def display_image(self, img, canvas, placeholder_text_id=None):
        # Clear previous content
        canvas.delete("all")
        
        # Calculate scaling to fit in the canvas
        canvas_width = canvas.winfo_width()
        canvas_height = canvas.winfo_height()
        
        # If the canvas hasn't been drawn yet, use reasonable defaults
        if canvas_width < 10:
            canvas_width = 300
        if canvas_height < 10:
            canvas_height = 300
            
        # Calculate scale factor
        img_width, img_height = img.size
        scale = min(canvas_width / img_width, canvas_height / img_height)
        
        # Resize the image
        new_width = int(img_width * scale)
        new_height = int(img_height * scale)
        img_resized = img.resize((new_width, new_height), Image.LANCZOS)
        
        # Convert to PhotoImage and keep a reference
        photo = ImageTk.PhotoImage(img_resized)
        canvas.image = photo  # Keep a reference to prevent garbage collection
        
        # Position the image in the center
        x_pos = (canvas_width - new_width) // 2
        y_pos = (canvas_height - new_height) // 2
        
        # Add the image to the canvas
        canvas.create_image(x_pos, y_pos, anchor=tk.NW, image=photo)

    def generate_file_hash(self, file_path):
        """Generate SHA-256 hash from file contents"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read the file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def get_password_data(self):
        """Get password data based on current mode"""
        if self.password_mode.get() == "simple":
            password = self.password_entry.get()
            if len(password) < 3:
                raise ValueError("Password must be at least 3 characters long")
            return password, "simple"
        else:
            if not self.password_hash:
                raise ValueError("Please select a password file")
            return self.password_hash, "advanced"

    def modify_seed_with_password(self, seed):
        """Apply password to seed via XOR"""
        try:
            # Get password data based on mode
            password_data, mode = self.get_password_data()
            
            # Create password hash
            password_bytes = password_data.encode('utf-8')
            password_hash = hashlib.sha256(password_bytes).digest()
            
            # Convert to 32-bit integers for XOR operation
            password_array = array.array('L', password_hash + password_hash[:8])  # 8 bytes to 32 bytes
            
            # XOR the seed with password hash
            modified_seed = np.zeros(32, dtype=np.uint32)
            for i in range(32):
                modified_seed[i] = seed[i] ^ password_array[i % len(password_array)]
            
            # Create base64 encoded truncated password for verification
            encoded_password = base64.b64encode(password_data.encode('utf-8')).decode('ascii')[:10]
            
            return {
                "seed": modified_seed,
                "mode": mode,
                "data": encoded_password
            }
        
        except ValueError as e:
            messagebox.showerror("Password Error", str(e))
            raise
            
    def encrypt_image(self):
        """Encrypt the loaded image"""
        if self.original_image is None:
            messagebox.showinfo("No Image", "Please select an image first!")
            return
        
        try:
            self.status_var.set("Encrypting image...")
            self.root.update()
            
            # Convert image to numpy array for processing
            img_array = np.array(self.original_image)
            
            # Generate secure random seed
            base_seed = np.array([secrets.randbits(32) for _ in range(32)], dtype=np.uint32)
            
            # Modify seed with password
            seed_data = self.modify_seed_with_password(base_seed)
            seed = seed_data["seed"]
            mode = seed_data["mode"]
            password_data = seed_data["data"]
            
            # Create metadata
            metadata = {
                "s": [int(x).to_bytes(4, byteorder='little').hex() for x in seed],  # Store seed as hex
                "m": mode[0],  # 's' for simple or 'a' for advanced
                "d": password_data,
                "v": "4"  # Version 4 - same as JS version
            }
            
            # Convert metadata to JSON string
            metadata_str = json.dumps(metadata)
            
            # Calculate steganography area
            signature = "ENKRPSHN"
            metadata_bytes = metadata_str.encode('utf-8')
            metadata_length = len(metadata_bytes)
            
            # Calculate reserved area for steganography
            total_bytes_needed = len(signature) + 4 + metadata_length  # signature + length + data
            total_bits_needed = total_bytes_needed * 8
            
            # Start offset for steganography (same as JS version)
            start_offset = 1000
            end_offset = start_offset + (total_bits_needed * 4)  # 4 bytes (RGBA) per bit
            
            # Check if image is big enough
            height, width = img_array.shape[:2]
            total_pixels = width * height
            total_bytes = total_pixels * 3
            
            if total_bits_needed > total_bytes:
                messagebox.showerror("Error", f"Image too small for metadata: needs {total_bits_needed} bits, have {total_bytes} bits")
                return
            
            # Create a copy of the image for encryption
            encrypted_array = img_array.copy()
            
            # Process each pixel for encryption (excluding steganography area)
            height, width = encrypted_array.shape[:2]
            
            # Encrypt each pixel
            for y in range(height):
                for x in range(width):
                    # Calculate pixel position
                    pixel_position = y * width + x
                    pixel_offset = pixel_position * (4 if img_array.shape[2] == 4 else 3)
                    
                    # Skip if this is in the steganography area
                    if pixel_offset >= start_offset and pixel_offset < end_offset:
                        continue
                    
                    # Encrypt the pixel
                    r, g, b = img_array[y, x, :3]  # Get RGB values
                    encrypted_pixel = self.encrypt_pixel(r, g, b, pixel_position, seed)
                    
                    # Set encrypted values
                    encrypted_array[y, x, 0] = encrypted_pixel["r"]
                    encrypted_array[y, x, 1] = encrypted_pixel["g"]
                    encrypted_array[y, x, 2] = encrypted_pixel["b"]
            
            # Embed steganography data
            self.embed_steganography(encrypted_array, metadata_str)
            
            # Convert back to PIL Image
            self.encrypted_image = Image.fromarray(encrypted_array)
            
            # Display the encrypted image
            self.display_image(self.encrypted_image, self.output_preview, self.output_placeholder_text)
            
            # Enable save button
            self.save_btn.configure(state=tk.NORMAL)
            
            self.status_var.set("Image encrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.status_var.set(f"Encryption failed: {str(e)}")

    def decrypt_image(self):
        """Decrypt the loaded image"""
        if self.original_image is None:
            messagebox.showinfo("No Image", "Please select an encrypted image first!")
            return
        
        try:
            self.status_var.set("Checking for encryption metadata...")
            self.root.update()
            
            # Check for embedded metadata
            metadata = self.check_for_steganography()
            
            if not metadata:
                messagebox.showerror("Not Encrypted", "This image doesn't appear to be encrypted with this system.")
                self.status_var.set("No encryption metadata found")
                return
            
            # Extract encryption details
            seed = metadata["seed"]
            stored_mode = metadata["mode"]
            stored_password_data = metadata["data"]
            version = metadata.get("version", "1")
            
            # Verify correct password mode
            current_mode = "simple" if self.password_mode.get() == "simple" else "advanced"
            if current_mode != stored_mode:
                messagebox.showinfo("Mode Mismatch", 
                                   f"This image was encrypted with {stored_mode} mode. Please switch to that mode.")
                return
            
            # Get current password data
            password_data, _ = self.get_password_data()
            
            # Verify password using stored data
            encoded_password = base64.b64encode(password_data.encode('utf-8')).decode('ascii')[:10]
            if encoded_password != stored_password_data:
                messagebox.showerror("Incorrect Password", "The password is incorrect for this encrypted image.")
                return
            
            self.status_var.set("Decrypting image...")
            self.root.update()
            
            # Convert image to numpy array
            img_array = np.array(self.original_image)
            
            # Create a copy for decryption
            decrypted_array = img_array.copy()
            
            # Calculate steganography area
            signature = "ENKRPSHN"
            metadata_str = json.dumps({
                "s": [x for x in seed],
                "m": stored_mode[0],
                "d": stored_password_data,
                "v": version
            })
            metadata_bytes = metadata_str.encode('utf-8')
            metadata_length = len(metadata_bytes)
            
            # Calculate reserved area
            total_bytes_needed = len(signature) + 4 + metadata_length
            total_bits_needed = total_bytes_needed * 8
            start_offset = 1000
            end_offset = start_offset + (total_bits_needed * 4)
            
            # Process each pixel for decryption (excluding steganography area)
            height, width = decrypted_array.shape[:2]
            
            # Decrypt each pixel
            for y in range(height):
                for x in range(width):
                    # Calculate pixel position
                    pixel_position = y * width + x
                    pixel_offset = pixel_position * (4 if img_array.shape[2] == 4 else 3)
                    
                    # Skip if this is in the steganography area
                    if pixel_offset >= start_offset and pixel_offset < end_offset:
                        continue
                    
                    # Get encrypted values
                    r, g, b = img_array[y, x, :3]
                    
                    # Decrypt based on version
                    if version == "4":
                        decrypted_pixel = self.decrypt_pixel(r, g, b, pixel_position, seed)
                    else:
                        # Legacy decryption
                        pixel_seed = seed[0] + pixel_position
                        decrypted_pixel = {
                            "r": self.legacy_decrypt_value(r, pixel_seed, seed),
                            "g": self.legacy_decrypt_value(g, pixel_seed + 1, seed),
                            "b": self.legacy_decrypt_value(b, pixel_seed + 2, seed)
                        }
                    
                    # Set decrypted values
                    decrypted_array[y, x, 0] = decrypted_pixel["r"]
                    decrypted_array[y, x, 1] = decrypted_pixel["g"]
                    decrypted_array[y, x, 2] = decrypted_pixel["b"]
            
            # Convert back to PIL Image
            self.encrypted_image = Image.fromarray(decrypted_array)
            
            # Display the decrypted image
            self.display_image(self.encrypted_image, self.output_preview, self.output_placeholder_text)
            
            # Enable save button
            self.save_btn.configure(state=tk.NORMAL)
            
            self.status_var.set("Image decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self.status_var.set(f"Decryption failed: {str(e)}")
            
    def murmurhash3(self, key, seed):
        """Implementation of MurmurHash3 for generating random values"""
        c1 = 0xcc9e2d51
        c2 = 0x1b873593
        length = len(key)
        h1 = seed & 0xffffffff
        roundedEnd = (length & 0xfffffffc)  # round down to 4 byte block
        
        # Body
        i = 0
        while i < roundedEnd:
            # Get 4 bytes as an int
            k1 = ((key[i] & 0xff) |
                 ((key[i + 1] & 0xff) << 8) |
                 ((key[i + 2] & 0xff) << 16) |
                 ((key[i + 3] & 0xff) << 24))
            
            k1 = (k1 * c1) & 0xffffffff
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff  # ROTL32(k1,15)
            k1 = (k1 * c2) & 0xffffffff
            
            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff  # ROTL32(h1,13)
            h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
            
            i += 4
            
        # Tail
        k1 = 0
        val = length & 0x03
        if val == 3:
            k1 = (key[roundedEnd + 2] & 0xff) << 16
        if val in [2, 3]:
            k1 |= (key[roundedEnd + 1] & 0xff) << 8
        if val in [1, 2, 3]:
            k1 |= key[roundedEnd] & 0xff
            k1 = (k1 * c1) & 0xffffffff
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff  # ROTL32(k1,15)
            k1 = (k1 * c2) & 0xffffffff
            h1 ^= k1
            
        # Finalization
        h1 ^= length
        h1 ^= h1 >> 16
        h1 = (h1 * 0x85ebca6b) & 0xffffffff
        h1 ^= h1 >> 13
        h1 = (h1 * 0xc2b2ae35) & 0xffffffff
        h1 ^= h1 >> 16
        
        return h1 & 0xffffffff

    def seed_random(self, seed, position):
        """Generate random value based on seed and position"""
        # Create unique identifier
        pos_str = str(position) + str(seed[0])
        pos_bytes = pos_str.encode('utf-8')
        
        # Use the murmurhash3 with seed value from array
        hash_value = self.murmurhash3(pos_bytes, seed[position % len(seed)])
        
        # Return a value between 0 and 255
        return hash_value % 256

    def encrypt_pixel(self, r, g, b, position, seed):
        """Strong encryption for a single pixel"""
        # Generate noise values
        noise_r = self.seed_random(seed, position)
        noise_g = self.seed_random(seed, position + 0xF1EA7)
        noise_b = self.seed_random(seed, position + 0xD06)
        
        # 1. Bitwise operations
        step1_r = (r ^ noise_r) & 0xFF
        step1_g = (g ^ noise_g) & 0xFF
        step1_b = (b ^ noise_b) & 0xFF
        
        # 2. Addition/modulo
        step2_r = (step1_r + noise_g) % 256
        step2_g = (step1_g + noise_b) % 256
        step2_b = (step1_b + noise_r) % 256
        
        # 3. Channel swapping
        swap_channels = position % 6
        
        if swap_channels == 0:
            final_r, final_g, final_b = step2_r, step2_g, step2_b  # RGB
        elif swap_channels == 1:
            final_r, final_g, final_b = step2_b, step2_r, step2_g  # BRG
        elif swap_channels == 2:
            final_r, final_g, final_b = step2_g, step2_b, step2_r  # GBR
        elif swap_channels == 3:
            final_r, final_g, final_b = step2_b, step2_g, step2_r  # BGR
        elif swap_channels == 4:
            final_r, final_g, final_b = step2_g, step2_r, step2_b  # GRB
        else:  # swap_channels == 5
            final_r, final_g, final_b = step2_r, step2_b, step2_g  # RBG
        
        return {
            "r": final_r,
            "g": final_g,
            "b": final_b
        }

    def decrypt_pixel(self, r, g, b, position, seed):
        """Strong decryption for a single pixel - inverse of encryption"""
        # Determine channel arrangement
        swap_channels = position % 6
        
        # Undo the channel swapping
        if swap_channels == 0:
            step2_r, step2_g, step2_b = r, g, b  # RGB
        elif swap_channels == 1:
            step2_r, step2_g, step2_b = g, b, r  # BRG
        elif swap_channels == 2:
            step2_r, step2_g, step2_b = b, r, g  # GBR
        elif swap_channels == 3:
            step2_r, step2_g, step2_b = b, g, r  # BGR
        elif swap_channels == 4:
            step2_r, step2_g, step2_b = g, r, b  # GRB
        else:  # swap_channels == 5
            step2_r, step2_g, step2_b = r, b, g  # RBG
            
        # Generate the same noise values used during encryption
        noise_r = self.seed_random(seed, position)
        noise_g = self.seed_random(seed, position + 0xF1EA7)
        noise_b = self.seed_random(seed, position + 0xD06)
        
        # Undo the addition/modulo
        step1_r = (step2_r - noise_g) % 256
        step1_g = (step2_g - noise_b) % 256
        step1_b = (step2_b - noise_r) % 256
        
        # Undo the XOR operations (XOR is its own inverse)
        orig_r = step1_r ^ noise_r
        orig_g = step1_g ^ noise_g
        orig_b = step1_b ^ noise_b
        
        return {
            "r": orig_r,
            "g": orig_g,
            "b": orig_b
        }
        
    def legacy_decrypt_value(self, encrypted_value, pixel_seed, seed):
        """Legacy decryption for backward compatibility"""
        # Reverse the encryption process
        shift = pixel_seed % 256
        
        # Undo the additional transformation
        decrypted_value = (encrypted_value - seed[0] % 256 + 256) % 256
        
        # Undo the XOR operation
        decrypted_value = (decrypted_value ^ shift) % 256
        
        return decrypted_value

    def embed_steganography(self, img_array, metadata_str):
        """Embed metadata into image using LSB steganography"""
        # Define signature
        signature = "ENKRPSHN"
        
        # Convert metadata to bytes
        metadata_bytes = metadata_str.encode('utf-8')
        metadata_length = len(metadata_bytes)
        
        # Starting offset for steganography
        start_offset = 1000
        byte_index = 0
        
        # Embed signature first
        for i, char in enumerate(signature):
            char_code = ord(char)
            for bit in range(8):
                bit_value = (char_code >> bit) & 1
                position = start_offset + (byte_index * 8 + bit) * 4
                
                # Calculate pixel coordinates
                pixel_index = position // 4
                y = pixel_index // img_array.shape[1]
                x = pixel_index % img_array.shape[1]
                
                # Modify the least significant bit
                if bit_value:
                    img_array[y, x, 0] |= 1  # Set LSB to 1
                else:
                    img_array[y, x, 0] &= ~1  # Set LSB to 0
            byte_index += 1
        
        # Embed metadata length (32-bit value)
        for bit in range(32):
            bit_value = (metadata_length >> bit) & 1
            position = start_offset + (byte_index * 8 + bit) * 4
            
            # Calculate pixel coordinates
            pixel_index = position // 4
            y = pixel_index // img_array.shape[1]
            x = pixel_index % img_array.shape[1]
            
            # Modify the least significant bit
            if bit_value:
                img_array[y, x, 0] |= 1  # Set LSB to 1
            else:
                img_array[y, x, 0] &= ~1  # Set LSB to 0
                
        byte_index += 4  # 4 bytes for length
        
        # Embed metadata bytes
        for i, byte in enumerate(metadata_bytes):
            for bit in range(8):
                bit_value = (byte >> bit) & 1
                position = start_offset + (byte_index * 8 + bit) * 4
                
                # Calculate pixel coordinates
                pixel_index = position // 4
                y = pixel_index // img_array.shape[1]
                x = pixel_index % img_array.shape[1]
                
                # Modify the least significant bit
                if bit_value:
                    img_array[y, x, 0] |= 1  # Set LSB to 1
                else:
                    img_array[y, x, 0] &= ~1  # Set LSB to 0
                    
            byte_index += 1

    def check_for_steganography(self):
        """Check if the loaded image contains encrypted metadata"""
        if self.original_image is None:
            return None
            
        try:
            # Convert to numpy array
            img_array = np.array(self.original_image)
            
            # Check if image is large enough
            if img_array.size < 1000 + 1024:
                return None
                
            # Start offset
            start_offset = 1000
            
            # Read signature
            signature = "ENKRPSHN"
            extracted_signature = ""
            
            for i in range(len(signature)):
                char_code = 0
                for bit in range(8):
                    position = start_offset + (i * 8 + bit) * 4
                    
                    # Calculate pixel coordinates
                    pixel_index = position // 4
                    y = pixel_index // img_array.shape[1]
                    x = pixel_index % img_array.shape[1]
                    
                    # Check if array index is valid
                    if y < img_array.shape[0] and x < img_array.shape[1]:
                        bit_value = img_array[y, x, 0] & 1
                        if bit_value:
                            char_code |= (1 << bit)
                    
                extracted_signature += chr(char_code)
                
            # Check for valid signature
            if extracted_signature != signature:
                return None
                
            # Read metadata length
            metadata_length = 0
            for bit in range(32):
                position = start_offset + ((len(signature) * 8) + bit) * 4
                
                # Calculate pixel coordinates
                pixel_index = position // 4
                y = pixel_index // img_array.shape[1]
                x = pixel_index % img_array.shape[1]
                
                # Get bit value
                bit_value = img_array[y, x, 0] & 1
                if bit_value:
                    metadata_length |= (1 << bit)
                    
            # Sanity check length
            if metadata_length <= 0 or metadata_length > 10000:
                return None
                
            # Read metadata bytes
            metadata_bytes = bytearray(metadata_length)
            base_offset = len(signature) + 4  # Signature + 4 bytes for length
            
            for i in range(metadata_length):
                byte = 0
                for bit in range(8):
                    position = start_offset + ((base_offset * 8) + (i * 8) + bit) * 4
                    
                    # Calculate pixel coordinates
                    pixel_index = position // 4
                    y = pixel_index // img_array.shape[1]
                    x = pixel_index % img_array.shape[1]
                    
                    # Get bit value
                    bit_value = img_array[y, x, 0] & 1
                    if bit_value:
                        byte |= (1 << bit)
                        
                metadata_bytes[i] = byte
                
            # Convert to string and parse JSON
            metadata_str = metadata_bytes.decode('utf-8')
            metadata = json.loads(metadata_str)
            
            # Convert seed from hex back to integers
            seed = np.array([int.from_bytes(bytes.fromhex(x), byteorder='little') for x in metadata["s"]], dtype=np.uint32)
            
            # Return full metadata
            return {
                "seed": seed,
                "mode": "simple" if metadata["m"] == "s" else "advanced",
                "data": metadata["d"],
                "version": metadata.get("v", "1")
            }
            
        except Exception as e:
            print(f"Error checking for steganography: {str(e)}")
            return None

    def save_image(self):
        """Save the encrypted/decrypted image"""
        if self.encrypted_image is None:
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            self.encrypted_image.save(file_path)
            self.status_var.set(f"Image saved to {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))
            self.status_var.set("Error saving image")

if __name__ == "__main__":
    # Set up the root window
    root = tk.Tk()
    root.title("Image Encryption Tool")
    
    # Add app icon if available
    try:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
        if os.path.exists(icon_path):
            icon = ImageTk.PhotoImage(file=icon_path)
            root.iconphoto(True, icon)
    except:
        pass  # Icon loading is optional
        
    app = ImageEncryptionApp(root)
    root.mainloop()