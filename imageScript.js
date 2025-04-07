// Global variables
let originalImage = null;
let resultImage = null;
let passwordFile = null;
let passwordHash = null;

// Image input handling
document.getElementById('image-input').addEventListener('change', function(e) {
  const file = e.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = function(event) {
      const img = new Image();
      img.onload = function() {
        originalImage = img;
        displayImagePreview(img, 'image-preview');
        document.getElementById('preview-placeholder').style.display = 'none';
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  }
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
  container.innerHTML = '';
  container.appendChild(img.cloneNode());
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

// Convert a 1024-bit seed (Uint32Array) to a hexadecimal string
function seedToHex(seed) {
  return Array.from(seed)
    .map(value => value.toString(16).padStart(8, '0'))
    .join('');
}

// Convert a hexadecimal string back to a 1024-bit seed (Uint32Array)
function hexToSeed(hex) {
  const seed = new Uint32Array(32);
  for (let i = 0; i < 32; i++) {
    seed[i] = parseInt(hex.slice(i * 8, (i + 1) * 8), 16);
  }
  return seed;
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

// Image encryption function
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
    
    // Generate base seed
    const baseSeed = get1024BitSeed();
    
    // Modify seed with password
    const { seed, mode, data: passwordData } = await modifySeedWithPassword(baseSeed);
    
    // Process each pixel with the encryption algorithm
    for (let i = 0; i < data.length; i += 4) {
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
    
    // Put the encrypted data back onto the canvas
    ctx.putImageData(imageData, 0, 0);
    
    // Create a new image from the canvas
    const encryptedImg = new Image();
    encryptedImg.onload = function() {
      // Display the encrypted image with metadata for decryption
      displayEncryptedImage(encryptedImg, seed, mode, passwordData);
    };
    encryptedImg.src = canvas.toDataURL('image/png');
  } catch (error) {
    alert('Encryption error: ' + error.message);
    console.error('Encryption error:', error);
  }
}

// Helper function to encrypt a single numeric value
function encryptValue(value, pixelSeed, seed) {
  // We'll use a simplified version of the text encryption algorithm
  // Convert value to binary and back to simulate the original algorithm's flow
  // But adapt to ensure we get a valid RGB value (0-255) at the end
  
  // Use the seed to create a "shift" for the value
  const shift = pixelSeed % 256;
  
  // Apply XOR operation (common in encryption)
  let encryptedValue = (parseInt(value) ^ shift) % 256;
  
  // Apply additional transformation based on the first seed value
  encryptedValue = (encryptedValue + seed[0] % 256) % 256;
  
  return encryptedValue;
}

// Display encrypted image and store seed for decryption
function displayEncryptedImage(img, seed, passwordMode, passwordData) {
  const outputContainer = document.getElementById('output-image');
  outputContainer.innerHTML = '';
  
  // Store encryption metadata in the image's dataset for decryption
  img.dataset.encryptionSeed = seedToHex(seed);
  img.dataset.passwordMode = passwordMode;
  img.dataset.passwordData = passwordData;
  outputContainer.appendChild(img);
  
  // Store for download
  resultImage = img;
  
  // Enable download button
  document.getElementById('download-btn').disabled = false;
}

// Image decryption function
async function decryptImage() {
  const outputContainer = document.getElementById('output-image');
  
  // Check if there's an encrypted image
  if (!outputContainer.querySelector('img')) {
    alert('No encrypted image to decrypt!');
    return;
  }
  
  try {
    const encryptedImg = outputContainer.querySelector('img');
    const seedHex = encryptedImg.dataset.encryptionSeed;
    const storedPasswordMode = encryptedImg.dataset.passwordMode;
    const storedPasswordData = encryptedImg.dataset.passwordData;
    
    if (!seedHex || !storedPasswordMode || !storedPasswordData) {
      alert('No encryption data found. This image may not be encrypted with this system.');
      return;
    }
    
    // Verify the correct password is being used
    const currentPasswordMode = document.querySelector('input[name="password-mode"]:checked').value;
    
    if (currentPasswordMode !== storedPasswordMode) {
      alert(`This image was encrypted with ${storedPasswordMode} mode. Please switch to that mode.`);
      return;
    }
    
    // Get the password based on the mode
    let passwordData;
    
    if (storedPasswordMode === 'simple') {
      // Get password from input
      const passwordInput = document.getElementById('simple-password');
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
    
    // Get the base seed
    const seed = hexToSeed(seedHex);
    
    // Create canvas for decryption
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = encryptedImg.width;
    canvas.height = encryptedImg.height;
    ctx.drawImage(encryptedImg, 0, 0);
    
    // Get image data
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;
    
    // Process each pixel with the decryption algorithm
    for (let i = 0; i < data.length; i += 4) {
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
      outputContainer.innerHTML = '';
      outputContainer.appendChild(decryptedImg);
      
      // Store for download
      resultImage = decryptedImg;
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