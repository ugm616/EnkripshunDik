// Global variables
let originalImage = null;
let resultImage = null;
let passwordFile = null;
let passwordHash = null;

// DOM ready handler
document.addEventListener('DOMContentLoaded', function() {
  console.log("Image encryption system initialized");
  console.log("Current settings: Metadata capacity = 1KB");
});

// Image input handling
document.getElementById('image-input').addEventListener('change', function(e) {
  const file = e.target.files[0];
  if (!file) return;
  
  console.log("Loading image:", file.name);
  const reader = new FileReader();
  reader.onload = function(event) {
    const img = new Image();
    img.onload = function() {
      originalImage = img;
      displayImagePreview(img, 'image-preview');
      
      // Hide placeholder text when an image is loaded
      const placeholder = document.getElementById('preview-placeholder');
      if (placeholder) {
        placeholder.style.display = 'none';
      }
      
      // Check if this is an encrypted image
      checkForSteganography(img).then(metadata => {
        console.log("Metadata check result:", metadata ? "Found" : "Not found");
        if (metadata) {
          console.log("Detected encrypted image with metadata:", metadata);
          
          // Display message that this is an encrypted image
          if (placeholder) {
            placeholder.textContent = 'Encrypted image detected. Use the Decrypt button to view original.';
            placeholder.style.display = 'block';
          }
          
          // Set password mode radio button to match the image's encryption mode
          const modeRadios = document.querySelectorAll('input[name="password-mode"]');
          modeRadios.forEach(radio => {
            if (radio.value === metadata.mode) {
              radio.checked = true;
              // Trigger the change event to update UI
              radio.dispatchEvent(new Event('change'));
            }
          });
        }
      }).catch(err => {
        console.error("Error checking for metadata:", err);
      });
    };
    img.src = event.target.result;
  };
  reader.readAsDataURL(file);
});

// Password mode selection
const passwordModeRadios = document.querySelectorAll('input[name="password-mode"]');
passwordModeRadios.forEach(radio => {
  radio.addEventListener('change', togglePasswordMode);
});

// Toggle between simple and advanced password modes
function togglePasswordMode() {
  const simpleContainer = document.getElementById('simple-password-container');
  const advancedContainer = document.getElementById('advanced-password-container');
  
  console.log("Password mode changed to:", this.value);
  
  if (this.value === 'simple') {
    simpleContainer.classList.remove('hidden');
    advancedContainer.classList.add('hidden');
  } else {
    simpleContainer.classList.add('hidden');
    advancedContainer.classList.remove('hidden');
  }
}

// Password file input handling
document.getElementById('password-file-input').addEventListener('change', async function(e) {
  const file = e.target.files[0];
  if (file) {
    passwordFile = file;
    const preview = document.getElementById('password-file-preview');
    preview.innerHTML = `<strong>File:</strong> ${file.name} (${formatFileSize(file.size)})`;
    preview.classList.add('has-file');
    
    // Generate a hash of the file to use as a password
    try {
      passwordHash = await generateFileHash(file);
    } catch (error) {
      console.error('Error generating file hash:', error);
    }
  }
});

// Format file size in a user-friendly way
function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' bytes';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

// Generate a hash from a file
async function generateFileHash(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = async function(event) {
      try {
        const arrayBuffer = event.target.result;
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        resolve(hashHex);
      } catch (error) {
        reject(error);
      }
    };
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// Display image in a container
function displayImagePreview(img, containerId) {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = '';
    container.appendChild(img.cloneNode());
  }
}

// Cryptographically secure random number generator for 1024-bit seed
function get1024BitSeed() {
  const array = new Uint32Array(32); // 32 x 32-bit = 1024-bit
  window.crypto.getRandomValues(array);
  return array;
}

// Fast, high-quality 32-bit hash function
function murmurhash3_32_gc(key, seed) {
  let remainder, bytes, h1, h1b, c1, c2, k1, i;
  
  remainder = key.length & 3; // key.length % 4
  bytes = key.length - remainder;
  h1 = seed;
  c1 = 0xcc9e2d51;
  c2 = 0x1b873593;
  i = 0;
  
  while (i < bytes) {
    k1 = 
      ((key.charCodeAt(i) & 0xff)) |
      ((key.charCodeAt(++i) & 0xff) << 8) |
      ((key.charCodeAt(++i) & 0xff) << 16) |
      ((key.charCodeAt(++i) & 0xff) << 24);
    ++i;
    
    k1 = ((((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16))) & 0xffffffff;
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = ((((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16))) & 0xffffffff;
    
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1b = ((((h1 & 0xffff) * 5) + ((((h1 >>> 16) * 5) & 0xffff) << 16))) & 0xffffffff;
    h1 = (((h1b & 0xffff) + 0x6b64) + ((((h1b >>> 16) + 0xe654) & 0xffff) << 16));
  }
  
  k1 = 0;
  
  switch (remainder) {
    case 3: k1 ^= (key.charCodeAt(i + 2) & 0xff) << 16;
    case 2: k1 ^= (key.charCodeAt(i + 1) & 0xff) << 8;
    case 1: k1 ^= (key.charCodeAt(i) & 0xff);
            
            k1 = (((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16)) & 0xffffffff;
            k1 = (k1 << 15) | (k1 >>> 17);
            k1 = (((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16)) & 0xffffffff;
            h1 ^= k1;
  }
  
  h1 ^= key.length;
  
  h1 ^= h1 >>> 16;
  h1 = (((h1 & 0xffff) * 0x85ebca6b) + ((((h1 >>> 16) * 0x85ebca6b) & 0xffff) << 16)) & 0xffffffff;
  h1 ^= h1 >>> 13;
  h1 = ((((h1 & 0xffff) * 0xc2b2ae35) + ((((h1 >>> 16) * 0xc2b2ae35) & 0xffff) << 16))) & 0xffffffff;
  h1 ^= h1 >>> 16;
  
  return h1 >>> 0;
}

// Generate pseudo-random values from seed and position
function seedRandom(seed, position) {
  // Create a unique identifier for this position
  const posStr = position.toString() + seed[0].toString();
  
  // Generate a hash value for this position
  const hashValue = murmurhash3_32_gc(posStr, seed[position % seed.length]);
  
  // Return a value between 0 and 255
  return hashValue % 256;
}

// Modify seed with password
async function modifySeedWithPassword(seed) {
  // Get the selected password mode
  const isSimpleMode = document.querySelector('input[name="password-mode"]:checked').value === 'simple';
  
  // Get the password based on the mode
  let passwordData;
  let passwordMode;
  
  if (isSimpleMode) {
    // Get password from input
    const passwordInput = document.getElementById('simple-password');
    const password = passwordInput.value.trim();
    
    // Validate password
    if (password.length < 3) {
      throw new Error("Password must be at least 3 characters long");
    }
    
    passwordData = password;
    passwordMode = 'simple';
  } else {
    // Use file hash as password
    if (!passwordHash) {
      throw new Error("Please select a password file");
    }
    
    passwordData = passwordHash;
    passwordMode = 'advanced';
  }
  
  // Create a password hash
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(passwordData);
  const passwordHashBuffer = await crypto.subtle.digest('SHA-256', passwordBytes);
  const passwordHashArray = new Uint32Array(passwordHashBuffer);
  
  // Combine the seed and password hash
  const modifiedSeed = new Uint32Array(32);
  for (let i = 0; i < 32; i++) {
    // XOR the seed with the password hash (with wrapping)
    modifiedSeed[i] = seed[i] ^ passwordHashArray[i % (passwordHashArray.length)];
  }
  
  return { 
    seed: modifiedSeed, 
    mode: passwordMode,
    data: btoa(passwordData).slice(0, 10) // Store a truncated, encoded version of the password for verification
  };
}

// STRONG ENCRYPTION: This will completely scramble the image
function encryptPixel(r, g, b, position, seed) {
  // Generate noise values derived from the seed and position
  const noiseR = seedRandom(seed, position);
  const noiseG = seedRandom(seed, position + 0xF1EA7);
  const noiseB = seedRandom(seed, position + 0xD06);
  
  // Apply multiple transformations to thoroughly scramble pixel values
  
  // 1. Bitwise operations to destroy color relationships
  const step1R = (r ^ noiseR) & 0xFF;
  const step1G = (g ^ noiseG) & 0xFF;
  const step1B = (b ^ noiseB) & 0xFF;
  
  // 2. Addition/modulo to shift color channels
  const step2R = (step1R + noiseG) % 256;
  const step2G = (step1G + noiseB) % 256;
  const step2B = (step1B + noiseR) % 256;
  
  // 3. Channel swapping based on seed values
  // This is especially effective at destroying recognizable patterns
  const swapChannels = position % 6; // 6 possible channel arrangements
  let finalR, finalG, finalB;
  
  switch(swapChannels) {
    case 0: finalR = step2R; finalG = step2G; finalB = step2B; break; // RGB
    case 1: finalR = step2B; finalG = step2R; finalB = step2G; break; // BRG
    case 2: finalR = step2G; finalG = step2B; finalB = step2R; break; // GBR
    case 3: finalR = step2B; finalG = step2G; finalB = step2R; break; // BGR
    case 4: finalR = step2G; finalG = step2R; finalB = step2B; break; // GRB
    case 5: finalR = step2R; finalG = step2B; finalB = step2G; break; // RBG
  }
  
  return { r: finalR, g: finalG, b: finalB };
}

// Decrypt a pixel - exact inverse of encryption for perfect restoration
function decryptPixel(r, g, b, position, seed) {
  // First determine which channel arrangement was used during encryption
  const swapChannels = position % 6;
  let step2R, step2G, step2B;
  
  // Undo the channel swapping
  switch(swapChannels) {
    case 0: step2R = r; step2G = g; step2B = b; break; // RGB
    case 1: step2R = g; step2G = b; step2B = r; break; // BRG
    case 2: step2R = b; step2G = r; step2B = g; break; // GBR
    case 3: step2R = b; step2G = g; step2B = r; break; // BGR
    case 4: step2R = g; step2G = r; step2B = b; break; // GRB
    case 5: step2R = r; step2G = b; step2B = g; break; // RBG
  }
  
  // Generate the same noise values used during encryption
  const noiseR = seedRandom(seed, position);
  const noiseG = seedRandom(seed, position + 0xF1EA7);
  const noiseB = seedRandom(seed, position + 0xD06);
  
  // Undo the addition/modulo operations
  const step1R = (step2R + 256 - noiseG) % 256;
  const step1G = (step2G + 256 - noiseB) % 256;
  const step1B = (step2B + 256 - noiseR) % 256;
  
  // Undo the XOR operations
  const origR = (step1R ^ noiseR) & 0xFF;
  const origG = (step1G ^ noiseG) & 0xFF;
  const origB = (step1B ^ noiseB) & 0xFF;
  
  return { r: origR, g: origG, b: origB };
}

// Image encryption function with strong visual scrambling
async function encryptImage() {
  if (!originalImage) {
    alert('Please select an image first!');
    return;
  }
  
  try {
    // Create canvas for image processing
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = originalImage.width;
    canvas.height = originalImage.height;
    ctx.drawImage(originalImage, 0, 0);
    
    // Get image data
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;
    
    // Make sure image is large enough to hold metadata
    const minPixels = 256;
    if (canvas.width * canvas.height < minPixels) {
      throw new Error("Image too small to encrypt - needs at least 256 pixels");
    }
    
    // Generate base seed
    const baseSeed = get1024BitSeed();
    
    // Modify seed with password
    const { seed, mode, data: passwordData } = await modifySeedWithPassword(baseSeed);
    
    // Create compact metadata
    const metadata = {
      s: Array.from(seed).map(v => v.toString(36)),
      m: mode.charAt(0),
      d: passwordData,
      v: "4" // Version number
    };
    
    // Convert metadata to JSON string
    const metadataStr = JSON.stringify(metadata);
    console.log("Embedding metadata:", metadataStr);
    
    // Calculate steganography area size
    const signature = "ENKRPSHN";
    const metadataBytes = new TextEncoder().encode(metadataStr);
    const metadataLength = metadataBytes.length;
    const totalBytesNeeded = signature.length + 4 + metadataLength;
    const totalBitsNeeded = totalBytesNeeded * 8;
    const startOffset = 1000; // Same as in embedSteganography
    
    // Calculate end of steganography area
    const endOffset = startOffset + (totalBitsNeeded * 4); // Each bit uses 4 bytes (RGBA)
    console.log(`Steganography area: ${startOffset} to ${endOffset}`);
    
    // Process each pixel with the encryption algorithm (EXCLUDING the steganography area)
    for (let i = 0; i < data.length; i += 4) {
      // Skip steganography area
      if (i >= startOffset && i < endOffset) {
        continue;
      }
      
      // Get RGB values (ignore alpha)
      const r = data[i];
      const g = data[i + 1];
      const b = data[i + 2];
      
      // Calculate pixel position 
      const pixelPosition = Math.floor(i / 4);
      
      // Apply strong encryption to completely scramble the pixel
      const encrypted = encryptPixel(r, g, b, pixelPosition, seed);
      
      // Set the encrypted RGB values
      data[i] = encrypted.r;
      data[i + 1] = encrypted.g;
      data[i + 2] = encrypted.b;
      // Alpha remains unchanged
    }
    
    // Use robust LSB steganography after encryption
    embedSteganography(data, canvas.width, canvas.height, metadataStr);
    
    // Put the encrypted data back onto the canvas
    ctx.putImageData(imageData, 0, 0);
    
    // Create a new image from the canvas
    const encryptedImg = new Image();
    encryptedImg.onload = function() {
      // Display the encrypted image
      const outputContainer = document.getElementById('output-image');
      if (outputContainer) {
        outputContainer.innerHTML = '';
        outputContainer.appendChild(encryptedImg);
      }
      
      // Store for download
      resultImage = encryptedImg;
      
      // Enable download button
      const downloadBtn = document.getElementById('download-btn');
      if (downloadBtn) {
        downloadBtn.disabled = false;
      }
    };
    encryptedImg.src = canvas.toDataURL('image/png');
    console.log("Encryption complete with maximum visual scrambling");
  } catch (error) {
    alert('Encryption error: ' + error.message);
    console.error('Encryption error:', error);
  }
}

// Embed metadata using LSB (Least Significant Bit) steganography
function embedSteganography(data, width, height, metadataStr) {
  // First, add a solid signature pattern that we can easily detect
  const signature = "ENKRPSHN"; // Our signature
  
  // Create a byte array with signature + metadata length + metadata
  const metadataBytes = new TextEncoder().encode(metadataStr);
  const metadataLength = metadataBytes.length;
  
  // Check if we have enough space in the image
  const totalBits = width * height * 3; // 3 bits per pixel (1 per RGB channel)
  const totalBytesNeeded = signature.length + 4 + metadataLength;
  const totalBitsNeeded = totalBytesNeeded * 8;
  
  if (totalBitsNeeded > totalBits) {
    throw new Error(`Image too small for metadata: needs ${totalBitsNeeded} bits, have ${totalBits} bits`);
  }
  
  console.log(`Using LSB steganography: embedding ${totalBytesNeeded} bytes (${totalBitsNeeded} bits)`);
  
  // Start embedding data at a specific offset to avoid header issues
  const startOffset = 1000; // Start at pixel 250 (x4 for RGBA)
  let byteIndex = 0;
  
  // Embed the signature first
  for (let i = 0; i < signature.length; i++) {
    const charCode = signature.charCodeAt(i);
    for (let bit = 0; bit < 8; bit++) {
      const bitValue = (charCode >> bit) & 1;
      const position = startOffset + (byteIndex * 8 + bit) * 4;
      
      // Only modify the LSB of the value
      if (bitValue) {
        data[position] |= 1; // Set LSB to 1
      } else {
        data[position] &= ~1; // Set LSB to 0
      }
    }
    byteIndex++;
  }
  
  // Embed the metadata length (32-bit value)
  for (let bit = 0; bit < 32; bit++) {
    const bitValue = (metadataLength >> bit) & 1;
    const position = startOffset + (byteIndex * 8 + bit) * 4;
    
    if (bitValue) {
      data[position] |= 1;
    } else {
      data[position] &= ~1;
    }
  }
  byteIndex += 4; // 4 bytes for length
  
  // Embed the metadata bytes
  for (let i = 0; i < metadataLength; i++) {
    const byte = metadataBytes[i];
    for (let bit = 0; bit < 8; bit++) {
      const bitValue = (byte >> bit) & 1;
      const position = startOffset + (byteIndex * 8 + bit) * 4;
      
      if (bitValue) {
        data[position] |= 1;
      } else {
        data[position] &= ~1;
      }
    }
    byteIndex++;
  }
  
  console.log(`Steganography complete: embedded ${byteIndex} bytes starting at offset ${startOffset}`);
}

// Read metadata using LSB steganography
async function checkForSteganography(img) {
  try {
    // Create a canvas to examine the image
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = img.width;
    canvas.height = img.height;
    ctx.drawImage(img, 0, 0);
    
    // Get image data
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;
    
    // Make sure image is large enough
    const startOffset = 1000; // Same as in embedding function
    if (data.length < startOffset + 1024) {
      console.log("Image too small to contain steganography");
      return null;
    }
    
    // Read signature
    const signature = "ENKRPSHN";
    let extractedSignature = "";
    
    for (let i = 0; i < signature.length; i++) {
      let charCode = 0;
      for (let bit = 0; bit < 8; bit++) {
        const position = startOffset + (i * 8 + bit) * 4;
        const bitValue = data[position] & 1;
        if (bitValue) {
          charCode |= (1 << bit);
        }
      }
      extractedSignature += String.fromCharCode(charCode);
    }
    
    console.log(`Found signature: "${extractedSignature}"`);
    
    // Check if this is our encrypted image
    if (extractedSignature !== signature) {
      console.log("No valid signature found");
      return null;
    }
    
    // Read metadata length (32-bit value)
    let metadataLength = 0;
    for (let bit = 0; bit < 32; bit++) {
      const position = startOffset + ((signature.length * 8) + bit) * 4;
      const bitValue = data[position] & 1;
      if (bitValue) {
        metadataLength |= (1 << bit);
      }
    }
    
    console.log(`Metadata length: ${metadataLength} bytes`);
    
    // Sanity check the length
    if (metadataLength <= 0 || metadataLength > 10000) {
      console.log("Invalid metadata length");
      return null;
    }
    
    // Read metadata bytes
    const metadataBytes = new Uint8Array(metadataLength);
    const baseOffset = signature.length + 4; // Signature + 4 bytes for length
    
    for (let i = 0; i < metadataLength; i++) {
      let byte = 0;
      for (let bit = 0; bit < 8; bit++) {
        const position = startOffset + ((baseOffset * 8) + (i * 8) + bit) * 4;
        const bitValue = data[position] & 1;
        if (bitValue) {
          byte |= (1 << bit);
        }
      }
      metadataBytes[i] = byte;
    }
    
    // Convert to string
    const metadataStr = new TextDecoder().decode(metadataBytes);
    console.log(`Raw metadata: ${metadataStr}`);
    
    // Parse metadata
    const metadata = JSON.parse(metadataStr);
    
    // Convert compact format back to full format
    return {
      seed: new Uint32Array(metadata.s.map(v => parseInt(v, 36))), // Convert from base36 back to numbers
      mode: metadata.m === 's' ? 'simple' : 'advanced',
      data: metadata.d,
      version: metadata.v || "1" // Default to version 1 if not specified
    };
    
  } catch (error) {
    console.error('Error checking for steganography:', error);
    return null;
  }
}

// Image decryption function with support for all versions
async function decryptImage() {
  if (!originalImage) {
    alert('Please select an encrypted image first!');
    return;
  }
  
  try {
    console.log("Starting decryption process");
    
    // Check if the image has embedded metadata using steganography
    const metadata = await checkForSteganography(originalImage);
    
    if (!metadata) {
      alert('No encryption metadata found. This image may not be encrypted with this system.');
      return;
    }
    
    // Extract encryption details
    const seed = metadata.seed;
    const storedPasswordMode = metadata.mode;
    const storedPasswordData = metadata.data;
    const version = metadata.version || "1";
    
    console.log(`Image encrypted with algorithm version: ${version}`);
    
    // Verify the correct password is being used
    const passwordModeElement = document.querySelector('input[name="password-mode"]:checked');
    if (!passwordModeElement) {
      alert('Please select a password mode.');
      return;
    }
    
    const currentPasswordMode = passwordModeElement.value;
    if (currentPasswordMode !== storedPasswordMode) {
      alert(`This image was encrypted with ${storedPasswordMode} mode. Please switch to that mode.`);
      return;
    }
    
    // Get the password based on the mode
    let passwordData;
    
    if (storedPasswordMode === 'simple') {
      // Get password from input
      const passwordInput = document.getElementById('simple-password');
      if (!passwordInput) {
        alert('Simple password input field not found.');
        return;
      }
      
      const password = passwordInput.value.trim();
      
      // Validate password
      if (password.length < 3) {
        throw new Error("Password must be at least 3 characters long");
      }
      
      passwordData = password;
    } else {
      // Use file hash as password
      if (!passwordHash) {
        throw new Error("Please select a password file");
      }
      
      passwordData = passwordHash;
    }
    
    // Verify password using the stored truncated data
    const encodedPassword = btoa(passwordData).slice(0, 10);
    if (encodedPassword !== storedPasswordData) {
      throw new Error("Incorrect password! Decryption failed.");
    }
    
    console.log("Password verified, proceeding with decryption");
    
    // Create canvas for decryption
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = originalImage.width;
    canvas.height = originalImage.height;
    ctx.drawImage(originalImage, 0, 0);
    
    // Get image data
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;
    
    // Calculate steganography area size
    const signature = "ENKRPSHN";
    const metadataStr = JSON.stringify({
      s: Array.from(seed).map(v => v.toString(36)),
      m: storedPasswordMode.charAt(0),
      d: storedPasswordData,
      v: version
    });
    const metadataBytes = new TextEncoder().encode(metadataStr);
    const metadataLength = metadataBytes.length;
    const totalBytesNeeded = signature.length + 4 + metadataLength;
    const totalBitsNeeded = totalBytesNeeded * 8;
    const startOffset = 1000; // Same as in embedSteganography
    
    // Calculate end of steganography area
    const endOffset = startOffset + (totalBitsNeeded * 4); // Each bit uses 4 bytes (RGBA)
    console.log(`Steganography area: ${startOffset} to ${endOffset}`);
    
    // Process each pixel with the decryption algorithm (EXCLUDING the steganography area)
    for (let i = 0; i < data.length; i += 4) {
      // Skip steganography area
      if (i >= startOffset && i < endOffset) {
        continue;
      }
      
      // Calculate pixel position
      const pixelPosition = Math.floor(i / 4);
      
      // Get RGB values
      const r = data[i];
      const g = data[i + 1];
      const b = data[i + 2];
      
      // Decrypt based on version
      let decrypted;
      
      if (version === "4") {
        // Use our new strong decryption
        decrypted = decryptPixel(r, g, b, pixelPosition, seed);
      }
      else {
        // Fallback for older versions - using your original algorithm
        // Just wrap the old decryption in an object format
        const pixelSeed = seed[0] + pixelPosition;
        const decryptedR = decryptValue(r, pixelSeed, seed);
        const decryptedG = decryptValue(g, pixelSeed + 1, seed);
        const decryptedB = decryptValue(b, pixelSeed + 2, seed);
        decrypted = { r: decryptedR, g: decryptedG, b: decryptedB };
      }
      
      // Set the decrypted RGB values
      data[i] = decrypted.r;
      data[i + 1] = decrypted.g;
      data[i + 2] = decrypted.b;
      // Alpha remains unchanged
    }
    
    // Put the decrypted data back onto the canvas
    ctx.putImageData(imageData, 0, 0);
    
    // Create a new image from the canvas
    const decryptedImg = new Image();
    decryptedImg.onload = function() {
      // Display the decrypted image
      const outputContainer = document.getElementById('output-image');
      if (outputContainer) {
        outputContainer.innerHTML = '';
        outputContainer.appendChild(decryptedImg);
      }
      
      // Store for download
      resultImage = decryptedImg;
      
      // Enable download button
      const downloadBtn = document.getElementById('download-btn');
      if (downloadBtn) {
        downloadBtn.disabled = false;
      }
      
      console.log("Decryption completed successfully");
    };
    decryptedImg.src = canvas.toDataURL('image/png');
  } catch (error) {
    alert('Decryption error: ' + error.message);
    console.error('Decryption error:', error);
  }
}

// Legacy decryption function for backward compatibility
function decryptValue(encryptedValue, pixelSeed, seed) {
  // Reverse the encryption process
  const shift = pixelSeed % 256;
  
  // Undo the additional transformation
  let decryptedValue = (encryptedValue - seed[0] % 256 + 256) % 256;
  
  // Undo the XOR operation
  decryptedValue = (decryptedValue ^ shift) % 256;
  
  return decryptedValue;
}

// Download button handler
document.getElementById('download-btn').addEventListener('click', function() {
  if (!resultImage) return;
  
  // Create a temporary link for download
  const link = document.createElement('a');
  link.download = 'processed_image.png';
  link.href = resultImage.src;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
});

// Button event listeners
document.getElementById('encrypt-btn').addEventListener('click', encryptImage);
document.getElementById('decrypt-btn').addEventListener('click', decryptImage);