// Helper functions
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

// Encryption function
function encrypt(text) {
  const seed = get1024BitSeed(); // Generate a 1024-bit cryptographically secure seed
  const asciiMap = createAsciiMap(seed);

  const binary = textToBinary(text);
  const counts = binaryToCounts(binary);

  const encryptedText = counts.split('').map((char, index) => {
    // Replace every 2nd, 3rd, or 4th digit with a random character
    if ((index + 1) % 2 === 0 || (index + 1) % 3 === 0 || (index + 1) % 4 === 0) {
      const options = asciiMap[char];
      return options[Math.floor(seededRandom(seed[0] + index) * options.length)];
    }
    return char;
  }).join('');

  // Encrypt the seed using a simple XOR cipher (for demonstration purposes)
  const encryptedSeed = seed.map((value, index) => value ^ 0xDEADBEEF); // XOR with a fixed key (replace with a stronger encryption method)
  const encryptedSeedHex = seedToHex(encryptedSeed);

  return `${encryptedText}|${encryptedSeedHex}`; // Append the encrypted seed in hexadecimal format
}

// Decryption function
function decrypt(encryptedTextWithSeed) {
  // Split the encrypted text and seed
  const [encryptedText, encryptedSeedHex] = encryptedTextWithSeed.split('|');
  const encryptedSeed = hexToSeed(encryptedSeedHex);

  // Decrypt the seed using the same XOR cipher
  const seed = encryptedSeed.map((value, index) => value ^ 0xDEADBEEF); // XOR with the same fixed key
  const asciiMap = createAsciiMap(seed);

  // Reverse the replacement process
  let counts = '';
  for (let i = 0; i < encryptedText.length; i++) {
    const char = encryptedText[i];
    if (/\d/.test(char)) {
      // If the character is a digit, keep it
      counts += char;
    } else {
      // If the character is not a digit, find its corresponding digit
      for (const [digit, chars] of Object.entries(asciiMap)) {
        if (chars.includes(char)) {
          counts += digit;
          break;
        }
      }
    }
  }

  // Reconstruct the binary string from the counts
  let binary = '';
  let currentChar = '0';
  for (const count of counts) {
    binary += currentChar.repeat(parseInt(count));
    currentChar = currentChar === '0' ? '1' : '0';
  }

  // Convert binary to plain text
  let plainText = '';
  for (let i = 0; i < binary.length; i += 8) {
    const byte = binary.slice(i, i + 8);
    plainText += String.fromCharCode(parseInt(byte, 2));
  }

  return plainText;
}

// Event listeners
document.getElementById('encrypt-btn').addEventListener('click', () => {
  const input = document.getElementById('input').value;
  const encrypted = encrypt(input);
  document.getElementById('output').value = encrypted;
});

document.getElementById('decrypt-btn').addEventListener('click', () => {
  const input = document.getElementById('input').value;
  const decrypted = decrypt(input);
  document.getElementById('output').value = decrypted;
});

// Copy text button
document.getElementById('copy-btn').addEventListener('click', () => {
  const output = document.getElementById('output');
  output.select();
  document.execCommand('copy');
  alert('Text copied to clipboard!');
});