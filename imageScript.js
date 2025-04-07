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

// Helper functions from the original script
function textToBinary(text) {
  return text.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('');
}

function binaryToCounts(binary) {
  let counts = [];
  let currentChar = binary[0];
  let count = 1;
  for (let i = 1; i < binary.length; i++) {
    if (binary[i] === currentChar) {
      count++;
    } else {
      counts.push(count);
      currentChar = binary[i];
      count = 1;
    }
  }
  counts.push(count);
  return counts.join('');
}

// Create a pool of characters (uppercase, lowercase, and non-English letters)
const characterPool = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  'ä', 'é', 'ñ', 'ø', 'ü', 'ç', 'ß', 'å', 'æ', 'ö', 'î', 'â', 'ê', 'û', 'ô', 'è', 'ï', 'ë', 'ì', 'ò', 'ù', 'ã', 'õ', 'á', 'í', 'ó',
  'Ä', 'É', 'Ñ', 'Ø', 'Ü', 'Ç', 'Å', 'Æ', 'Ö', 'Î', 'Â', 'Ê', 'Û', 'Ô', 'È', 'Ï', 'Ë', 'Ì', 'Ò', 'Ù', 'Ã', 'Õ', 'Á', 'Í', 'Ó',
  'α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ', 'ι', 'κ', 'λ', 'μ', 'ν', 'ξ', 'ο', 'π', 'ρ', 'σ', 'τ', 'υ', 'φ', 'χ', 'ψ', 'ω',
  'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ'
];

// Cryptographically secure random number generator for 1024-bit seed
function get1024BitSeed() {
  const array = new Uint32Array(32); // 32 x 32-bit = 1024-bit
  window.crypto.getRandomValues(array);
  return array;
}

// Seeded random number generator (for shuffling)
function seededRandom(seed) {
  let x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
}

// Shuffle the character pool using a 1024-bit seed
function shuffleArrayWithSeed(array, seed) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(seededRandom(seed) * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
    seed++; // Update the seed for the next iteration
  }
  return array;
}

// Generate the asciiMap using a 1024-bit seed
function createAsciiMap(seed) {
  const shuffledPool = shuffleArrayWithSeed([...characterPool], seed);
  const asciiMap = {
    1: shuffledPool.slice(0, 26), // First 26 characters for digit 1
    2: shuffledPool.slice(26, 52), // Next 26 characters for digit 2
    3: shuffledPool.slice(52, 78), // Next 26 characters for digit 3
    4: shuffledPool.slice(78, 104), // Next 26 characters for digit 4
    5: shuffledPool.slice(104, 130), // Next 26 characters for digit 5
    6: shuffledPool.slice(130, 156) // Remaining characters for digit 6
  };
  return asciiMap;
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

// Image encryption function - UPDATED to exclude steganography area
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
      v: "1"
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
      
      // Convert to binary strings
      const rBinary = r.toString(2).padStart(8, '0');
      const gBinary = g.toString(2).padStart(8, '0');
      const bBinary = b.toString(2).padStart(8, '0');
      
      // Apply the binary counts encryption logic from the original algorithm
      const rCounts = binaryToCounts(rBinary);
      const gCounts = binaryToCounts(gBinary);
      const bCounts = binaryToCounts(bBinary);
      
      // Create pixel signature for consistent encryption
      const pixelIndex = Math.floor(i / 4);
      const pixelSeed = seed[0] + pixelIndex;
      
      // Encrypt RGB using the original technique
      const encryptedR = encryptValue(rCounts, pixelSeed, seed);
      const encryptedG = encryptValue(gCounts, pixelSeed + 1, seed);
      const encryptedB = encryptValue(bCounts, pixelSeed + 2, seed);
      
      // Set the modified RGB values
      data[i] = encryptedR;
      data[i + 1] = encryptedG;
      data[i + 2] = encryptedB;
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
    console.log("Encryption complete");
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
  let bitIndex = 0;
  
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
      version: metadata.v
    };
    
  } catch (error) {
    console.error('Error checking for steganography:', error);
    return null;
  }
}

// Helper function to encrypt a single numeric value
function encryptValue(value, pixelSeed, seed) {
  // Use the seed to create a "shift" for the value
  const shift = pixelSeed % 256;
  
  // Apply XOR operation
  let encryptedValue = (parseInt(value) ^ shift) % 256;
  
  // Apply additional transformation based on the first seed value
  encryptedValue = (encryptedValue + seed[0] % 256) % 256;
  
  return encryptedValue;
}

// Image decryption function - UPDATED to exclude steganography area
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
      v: "1"
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
      
      // Get encrypted RGB values
      const encryptedR = data[i];
      const encryptedG = data[i + 1];
      const encryptedB = data[i + 2];
      
      // Create pixel signature for consistent decryption
      const pixelIndex = Math.floor(i / 4);
      const pixelSeed = seed[0] + pixelIndex;
      
      // Decrypt RGB values
      const decryptedR = decryptValue(encryptedR, pixelSeed, seed);
      const decryptedG = decryptValue(encryptedG, pixelSeed + 1, seed);
      const decryptedB = decryptValue(encryptedB, pixelSeed + 2, seed);
      
      // Set the decrypted RGB values
      data[i] = decryptedR;
      data[i + 1] = decryptedG;
      data[i + 2] = decryptedB;
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

// Helper function to decrypt a single value
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