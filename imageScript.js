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
    
    // Make sure image is large enough to hold metadata
    const minPixels = 100; // Need at least 100 pixels for metadata
    if (canvas.width * canvas.height < minPixels) {
      throw new Error("Image too small to encrypt - needs at least 100 pixels");
    }
    
    // Generate base seed
    const baseSeed = get1024BitSeed();
    
    // Modify seed with password
    const { seed, mode, data: passwordData } = await modifySeedWithPassword(baseSeed);
    
    // Reserve the last rows of pixels for metadata
    const reservedPixels = 100;
    const reservedBytes = reservedPixels * 4;
    const dataLimit = data.length - reservedBytes;
    
    // Process each pixel with the encryption algorithm (skip reserved area)
    for (let i = 0; i < dataLimit; i += 4) {
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
    
    // Create compact metadata
    const metadata = {
      s: Array.from(seed).map(v => v.toString(36)), // Convert to base36 for shorter strings
      m: mode.charAt(0), // 's' for simple, 'a' for advanced
      d: passwordData,
      v: "1"
    };
    
    // Convert metadata to JSON string
    const metadataStr = JSON.stringify(metadata);
    
    // Embed metadata into the image
    embedMetadataIntoImage(data, metadataStr, dataLimit);
    
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
  } catch (error) {
    alert('Encryption error: ' + error.message);
    console.error('Encryption error:', error);
  }
}

// Embed metadata into the image data
function embedMetadataIntoImage(data, metadataStr, dataLimit) {
  // Calculate positions
  const sigLength = 4; // 4 characters for signature "EIMG"
  const metadataLength = metadataStr.length;
  
  // Calculate how many pixels we need
  const totalBytesNeeded = metadataLength + sigLength + 4; // +4 for length storage
  const totalPixelsNeeded = Math.ceil(totalBytesNeeded / 3); // Each pixel can store 3 bytes (R,G,B)
  
  // Make sure we have enough space
  const availablePixels = Math.floor((data.length - dataLimit) / 4);
  if (totalPixelsNeeded > availablePixels) {
    throw new Error(`Metadata too large: needs ${totalPixelsNeeded} pixels, have ${availablePixels}`);
  }
  
  // Write signature at the start of the reserved area
  let position = dataLimit;
  for (let i = 0; i < sigLength; i++) {
    data[position++] = "EIMG".charCodeAt(i);
  }
  
  // Write metadata length (16-bit value)
  data[position++] = metadataLength & 0xFF;
  data[position++] = (metadataLength >> 8) & 0xFF;
  
  // Write the metadata characters
  for (let i = 0; i < metadataLength; i++) {
    data[position++] = metadataStr.charCodeAt(i);
  }
}

// Check if an image has embedded encryption metadata
async function checkForEmbeddedMetadata(img) {
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
    if (data.length < 400) return null; // Need at least 100 pixels
    
    // Calculate reserved area start
    const dataLimit = data.length - 400;
    
    // Read signature from the beginning of reserved area
    let position = dataLimit;
    let signature = '';
    for (let i = 0; i < 4; i++) {
      signature += String.fromCharCode(data[position++]);
    }
    
    // Check if this is our encrypted image
    if (signature !== 'EIMG') {
      return null;
    }
    
    // Read metadata length (16-bit value)
    const lengthLow = data[position++];
    const lengthHigh = data[position++];
    const metadataLength = lengthLow | (lengthHigh << 8);
    
    // Read metadata characters
    let metadataStr = '';
    for (let i = 0; i < metadataLength; i++) {
      metadataStr += String.fromCharCode(data[position++]);
    }
    
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
    console.error('Error checking for embedded metadata:', error);
    return null;
  }
}