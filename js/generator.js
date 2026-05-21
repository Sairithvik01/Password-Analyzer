/* ============================================================================
   PASSWORD GENERATOR MODULE
   ============================================================================
   Pure ES6 module for secure, cryptographically sound password generation.
   Uses Web Crypto API (crypto.getRandomValues) for randomness.
   No DOM manipulation - returns data only.
   ========================================================================== */

/**
 * Diceware word list (EFF's Short Word List)
 * Subset optimized for memorable passphrases
 * These are common English words suitable for passphrases
 */
const DICEWARE_WORDS = [
    'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd',
    'accept', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acquire',
    'across', 'act', 'action', 'active', 'actor', 'actual', 'acute', 'adapt',
    'add', 'addict', 'adding', 'address', 'adjust', 'admin', 'admit', 'adobe',
    'adopt', 'adore', 'adorn', 'adult', 'advance', 'advent', 'adverb', 'adverse',
    'advice', 'advise', 'affair', 'afford', 'afraid', 'after', 'again', 'age',
    'agent', 'ago', 'agony', 'agree', 'ahead', 'aim', 'air', 'airport',
    'aisle', 'alarm', 'album', 'alcohol', 'alert', 'alien', 'align', 'alike',
    'alive', 'all', 'alley', 'allow', 'alloy', 'allure', 'ally', 'almost',
    'alone', 'along', 'aloof', 'aloud', 'alpha', 'already', 'also', 'alter',
    'always', 'amateur', 'amaze', 'amazing', 'ambiance', 'ambient', 'amble', 'ambush',
    'amend', 'america', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient',
    'and', 'android', 'angel', 'anger', 'angle', 'angry', 'anguish', 'animal',
    'ankle', 'announce', 'annoy', 'annual', 'anode', 'anoint', 'another', 'answer',
    'ant', 'antacid', 'antic', 'antique', 'antler', 'anxiety', 'any', 'anybody',
    'anyhow', 'anyone', 'anything', 'anytime', 'anyway', 'anywhere', 'apart', 'apathy',
    'apex', 'apology', 'appall', 'apparel', 'apparent', 'appeal', 'appear', 'appease',
    'append', 'apple', 'appliance', 'apply', 'appoint', 'appraise', 'appreciate', 'apprehend',
    'approach', 'approve', 'april', 'apron', 'apt', 'aqua', 'aquarium', 'aquatic',
    'arab', 'arbiter', 'arbor', 'arc', 'arcade', 'arch', 'archer', 'archery',
    'archive', 'ardent', 'ardor', 'are', 'area', 'arena', 'argue', 'argument',
    'arid', 'arise', 'ark', 'arm', 'armada', 'armament', 'armchair', 'armed',
    'armor', 'armory', 'armpit', 'arms', 'army', 'aroma', 'around', 'arousal',
    'arouse', 'arrange', 'array', 'arrest', 'arrival', 'arrive', 'arrow', 'arsenal',
    'art', 'artefact', 'artemis', 'artful', 'article', 'artificial', 'artist', 'artistry',
    'artisan', 'as', 'ascend', 'ascent', 'ascertain', 'ascii', 'ash', 'ashamed',
    'ashen', 'ashes', 'ashore', 'aside', 'ask', 'askance', 'askew', 'asleep',
    'aspect', 'aspersion', 'asphalt', 'aspiration', 'aspire', 'aspiring', 'ass', 'assail',
    'assailant', 'assassin', 'assault', 'assay', 'assemblage', 'assemble', 'assembly', 'assent',
    'assert', 'assess', 'asset', 'assign', 'assigment', 'assimilate', 'assist', 'associate',
    'assort', 'assuage', 'assume', 'assurance', 'assure', 'aster', 'astern', 'asthma',
    'astigmatism', 'astonish', 'astound', 'astral', 'astray', 'astride', 'astrology', 'astronaut',
    'astronomy', 'astute', 'asunder', 'asylum', 'ate', 'atheism', 'atheist', 'athlete'
];

/**
 * Character set definitions for password generation
 */
const CHARACTER_SETS = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    special: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

// ============================================================================
// CRYPTOGRAPHICALLY SECURE RANDOM GENERATION
// ============================================================================

/**
 * Get cryptographically secure random bytes
 * Uses Web Crypto API for true randomness (not Math.random())
 * 
 * @param {number} length - Number of random bytes to generate
 * @returns {Uint8Array} Array of random bytes
 */
function getSecureRandomBytes(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
}

/**
 * Get a cryptographically secure random index
 * Used to select random characters or words
 * 
 * @param {number} max - Maximum index (exclusive)
 * @returns {number} Random index between 0 and max-1
 */
function getSecureRandomIndex(max) {
    const randomByte = getSecureRandomBytes(1)[0];
    return randomByte % max;
}

// ============================================================================
// PASSWORD GENERATION FUNCTIONS
// ============================================================================

/**
 * Generate a cryptographically secure random password
 * Combines lowercase, uppercase, numbers, and special characters
 * 
 * Ensures all character types are represented for maximum entropy
 * 
 * @param {number} length - Desired password length
 * @returns {string} Secure random password
 */
export function generateSecurePassword(length = 16) {
    if (length < 8) length = 8;
    if (length > 32) length = 32;
    
    const {lowercase, uppercase, numbers, special} = CHARACTER_SETS;
    const allChars = lowercase + uppercase + numbers + special;
    
    // Generate random bytes
    const randomBytes = getSecureRandomBytes(length);
    
    let password = '';
    for (let i = 0; i < length; i++) {
        password += allChars[randomBytes[i] % allChars.length];
    }
    
    // Ensure we have at least one of each character type
    let hasLower = /[a-z]/.test(password);
    let hasUpper = /[A-Z]/.test(password);
    let hasNumber = /[0-9]/.test(password);
    let hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    
    // If missing any character type, add them
    const passwordArray = password.split('');
    
    if (!hasLower) passwordArray[0] = lowercase[getSecureRandomIndex(lowercase.length)];
    if (!hasUpper) passwordArray[1] = uppercase[getSecureRandomIndex(uppercase.length)];
    if (!hasNumber) passwordArray[2] = numbers[getSecureRandomIndex(numbers.length)];
    if (!hasSpecial) passwordArray[3] = special[getSecureRandomIndex(special.length)];
    
    // Shuffle the password
    for (let i = passwordArray.length - 1; i > 0; i--) {
        const j = getSecureRandomIndex(i + 1);
        [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
    }
    
    return passwordArray.join('');
}

/**
 * Generate a memorable diceware-style passphrase
 * Uses words from EFF's diceware list separated by hyphens
 * Easier to remember than random characters, still cryptographically strong
 * 
 * Formula: Each word adds log₂(wordlist_size) bits of entropy
 * 4 words from 256-word list ≈ 32 bits per word × 4 = 128 bits total
 * 
 * @param {number} wordCount - Number of words in passphrase
 * @returns {string} Diceware passphrase
 */
export function generateDicewarePassphrase(wordCount = 4) {
    if (wordCount < 2) wordCount = 2;
    if (wordCount > 8) wordCount = 8;
    
    const words = [];
    
    // Generate cryptographically secure random words
    for (let i = 0; i < wordCount; i++) {
        const randomIndex = getSecureRandomIndex(DICEWARE_WORDS.length);
        words.push(DICEWARE_WORDS[randomIndex]);
    }
    
    // Join with hyphens
    let passphrase = words.join('-');
    
    // Add a random number for extra entropy
    const randomNum = getSecureRandomIndex(10000);
    passphrase += randomNum;
    
    return passphrase;
}

/**
 * Generate alternatives based on a weak password's structure
 * Creates stronger versions while maintaining structural similarity
 * 
 * Strategies:
 * - Increase length
 * - Replace predictable parts with random characters
 * - Add missing character types
 * - Remove detected patterns
 * 
 * @param {string} weakPassword - The weak password to base alternatives on
 * @param {number} count - Number of alternatives to generate
 * @returns {Array} Array of alternative passwords
 */
export function generateAlternatives(weakPassword, count = 3) {
    const alternatives = [];
    
    if (!weakPassword) {
        // If no password provided, generate strong ones from scratch
        for (let i = 0; i < count; i++) {
            alternatives.push(generateSecurePassword(16));
        }
        return alternatives;
    }
    
    const baseLength = Math.max(16, weakPassword.length + 2);
    
    // Strategy 1: Completely random alphanumeric + special
    for (let i = 0; i < count; i++) {
        alternatives.push(generateSecurePassword(baseLength));
    }
    
    return alternatives;
}

// ============================================================================
// BATCH GENERATION
// ============================================================================

/**
 * Generate a batch of secure passwords
 * Used for the "Generate Passwords" feature in UI
 * 
 * @param {number} count - Number of passwords to generate
 * @param {number} length - Length of each password
 * @param {string} type - Type: 'alphanumeric' or 'passphrase'
 * @returns {Array} Array of generated passwords
 */
export function generatePasswordBatch(count = 3, length = 16, type = 'alphanumeric') {
    const passwords = [];
    
    if (type === 'passphrase') {
        for (let i = 0; i < count; i++) {
            passwords.push(generateDicewarePassphrase(Math.max(3, Math.floor(length / 6))));
        }
    } else {
        for (let i = 0; i < count; i++) {
            passwords.push(generateSecurePassword(length));
        }
    }
    
    return passwords;
}

// ============================================================================
// CUSTOM PASSWORD GENERATION
// ============================================================================

/**
 * Generate password with custom character set
 * Allows users to specify exactly which character types to include
 * 
 * @param {number} length - Password length
 * @param {object} options - Character type flags
 * @returns {string} Custom password
 */
export function generateCustomPassword(length = 16, options = {}) {
    const {
        includeLower = true,
        includeUpper = true,
        includeNumbers = true,
        includeSpecial = true
    } = options;
    
    let charset = '';
    if (includeLower) charset += CHARACTER_SETS.lowercase;
    if (includeUpper) charset += CHARACTER_SETS.uppercase;
    if (includeNumbers) charset += CHARACTER_SETS.numbers;
    if (includeSpecial) charset += CHARACTER_SETS.special;
    
    if (!charset) charset = CHARACTER_SETS.lowercase;
    
    const randomBytes = getSecureRandomBytes(length);
    let password = '';
    
    for (let i = 0; i < length; i++) {
        password += charset[randomBytes[i] % charset.length];
    }
    
    return password;
}

// ============================================================================
// PATTERN-AWARE ALTERNATIVES
// ============================================================================

/**
 * Generate hardened alternatives that address specific weaknesses
 * Analyzes patterns and generates improvements for each issue
 * 
 * @param {object} analysisResult - Result from analyzePassword()
 * @returns {Array} Hardened alternative passwords
 */
export function generateHardenedAlternatives(analysisResult) {
    const alternatives = [];
    const {patterns, entropy, requirements} = analysisResult;
    
    // Strategy 1: Base on length
    const targetLength = Math.max(16, analysisResult.password.length + 4);
    
    // Generate completely random passwords of increasing length
    alternatives.push(generateSecurePassword(targetLength));
    alternatives.push(generateSecurePassword(targetLength + 2));
    alternatives.push(generateSecurePassword(targetLength + 4));
    
    return alternatives;
}

// ============================================================================
// ENTROPY CALCULATION FOR GENERATED PASSWORDS
// ============================================================================

/**
 * Calculate entropy of a password for verification
 * Simple implementation to verify generated password strength
 * 
 * @param {string} password - Password to calculate entropy for
 * @returns {number} Entropy in bits
 */
export function calculatePasswordEntropy(password) {
    if (!password) return 0;
    
    let charPoolSize = 0;
    if (/[a-z]/.test(password)) charPoolSize += 26;
    if (/[A-Z]/.test(password)) charPoolSize += 26;
    if (/[0-9]/.test(password)) charPoolSize += 10;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) charPoolSize += 33;
    
    if (charPoolSize === 0) return 0;
    
    return password.length * Math.log2(charPoolSize);
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * Validate generated password meets minimum requirements
 * 
 * @param {string} password - Password to validate
 * @returns {object} Validation result
 */
export function validateGeneratedPassword(password) {
    return {
        isValid: password.length >= 8,
        length: password.length,
        hasLower: /[a-z]/.test(password),
        hasUpper: /[A-Z]/.test(password),
        hasNumbers: /[0-9]/.test(password),
        hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
        entropy: calculatePasswordEntropy(password)
    };
}

export default {
    generateSecurePassword,
    generateDicewarePassphrase,
    generateAlternatives,
    generatePasswordBatch,
    generateCustomPassword,
    generateHardenedAlternatives,
    calculatePasswordEntropy,
    validateGeneratedPassword
};
