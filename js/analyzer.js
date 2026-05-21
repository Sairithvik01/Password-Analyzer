/* ============================================================================
   PASSWORD ANALYZER MODULE
   ============================================================================
   Pure calculation module for password strength analysis.
   No DOM manipulation - pure functions only.
   Exports all analysis functions for use by the main orchestrator.
   ========================================================================== */

/**
 * Configuration constants for analysis
 */
const ANALYZER_CONFIG = {
    MIN_PASSWORD_LENGTH: 12,
    GUESSES_PER_SECOND: 100_000_000_000, // 100 billion (modern GPU cluster)
    MAX_ENTROPY: 128,
    ENTROPY_THRESHOLD_STRONG: 70,
    ENTROPY_THRESHOLD_MEDIUM: 40
};

/**
 * Top 50 most common passwords for dictionary attack detection
 * Source: Real-world breach data compilations
 */
const COMMON_PASSWORDS = [
    '123456', 'password', '123456789', '12345678', '12345', '1234567',
    'password123', '123123', '1234567890', '000000', '111111', '123321',
    '666666', '654321', '555555', '123456789', '987654321', 'qwerty',
    'abc123', 'million2', 'help123', 'password1', 'welcome', 'dragon',
    'master', 'monkey', 'shadow', 'sunshine', 'ashley', 'bailey',
    'passw0rd', '1q2w3e4r', 'admin', 'letmein', 'login', 'princess',
    'qwerty123', '123qwe', 'batman', 'superman', 'trustno1', 'solo',
    'starwars', 'football', 'baseball', 'iloveyou', 'sunshine'
];

/**
 * Keyboard pattern sequences for pattern detection
 * Detects common keyboard shortcuts and sequential patterns
 */
const KEYBOARD_PATTERNS = [
    // QWERTY rows
    'qwerty', 'qwertyuiop', 'asdf', 'asdfghjkl', 'zxcvbnm',
    // Diagonal patterns
    'qazwsx', 'qweasd', 'asdfgh',
    // Number sequences
    '12345', '123456', '1234567', '12345678',
    // Letter sequences
    'abcdef', 'abcdefg', 'abcd', 'abc'
];

// ============================================================================
// ENTROPY CALCULATION FUNCTIONS
// ============================================================================

/**
 * Calculate the character pool size based on password composition
 * Determines how many unique characters could be used
 * @param {string} password - The password to analyze
 * @returns {number} Total possible characters in pool
 * 
 * Example: Password with lowercase, uppercase, and numbers = 26+26+10 = 62
 */
export function calculateCharPool(password) {
    let pool = 0;
    
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);

    if (hasLower) pool += 26;    // a-z
    if (hasUpper) pool += 26;    // A-Z
    if (hasNumbers) pool += 10;  // 0-9
    if (hasSpecial) pool += 33;  // Special characters (~!@#$%^&*()_+-={}[]|;:'",.<>?/`)

    return pool === 0 ? 1 : pool;
}

/**
 * Calculate Shannon Entropy
 * Formula: H(X) = L × log₂(C)
 * Where L = password length, C = character pool size
 * 
 * Higher entropy = more secure (harder to predict/brute force)
 * 40 bits = moderate security
 * 70 bits = strong security
 * 128 bits = enterprise security
 * 
 * @param {string} password - The password to analyze
 * @returns {number} Entropy in bits
 */
export function calculateEntropy(password) {
    if (!password || password.length === 0) return 0;
    
    const charPool = calculateCharPool(password);
    const length = password.length;
    
    // H(X) = L × log₂(C)
    const entropy = length * Math.log2(charPool);
    
    return Math.max(0, entropy);
}

/**
 * Calculate total possible character combinations
 * Formula: CharPool ^ Length
 * 
 * This represents the total search space for brute force attacks
 * 
 * @param {string} password - The password to analyze
 * @returns {number} Total possible combinations
 */
export function calculateCombinations(password) {
    if (!password || password.length === 0) return 0;
    
    const charPool = calculateCharPool(password);
    const length = password.length;
    
    // C = Pool^Length
    const combinations = Math.pow(charPool, length);
    
    return combinations;
}

// ============================================================================
// TIME-TO-CRACK ESTIMATION
// ============================================================================

/**
 * Calculate estimated time to crack via brute force
 * Assumes modern GPU cluster capable of 100 billion guesses per second
 * 
 * Formula: Time = Total Combinations / (Guesses Per Second × 2)
 * (Divided by 2 because on average you crack it halfway through)
 * 
 * @param {number} entropy - Entropy in bits (2^entropy = total combinations)
 * @param {number} guessesPerSecond - Attack speed (default: 100B/sec)
 * @returns {string} Human-readable time estimate
 */
export function calculateCrackTime(entropy, guessesPerSecond = ANALYZER_CONFIG.GUESSES_PER_SECOND) {
    if (entropy === 0) return 'Instant';
    if (entropy < 0) return 'Instant';
    
    try {
        // Total possible combinations = 2^entropy
        const totalCombinations = Math.pow(2, entropy);
        
        // Average time to crack = combinations / (guesses/sec × 2)
        // We divide by 2 because statistically you find it halfway through
        const secondsToHack = totalCombinations / (guessesPerSecond * 2);

        // Format the result based on magnitude
        if (secondsToHack < 1) return 'Instant';
        if (secondsToHack < 60) return `${secondsToHack.toFixed(1)} seconds`;
        
        const minutesToHack = secondsToHack / 60;
        if (minutesToHack < 60) return `${minutesToHack.toFixed(1)} minutes`;
        
        const hoursToHack = minutesToHack / 60;
        if (hoursToHack < 24) return `${hoursToHack.toFixed(1)} hours`;
        
        const daysToHack = hoursToHack / 24;
        if (daysToHack < 365) return `${daysToHack.toFixed(1)} days`;
        
        const yearsToHack = daysToHack / 365;
        if (yearsToHack < 1_000_000) {
            return `${Math.floor(yearsToHack).toLocaleString()} years`;
        }
        
        return 'Essentially impossible';
    } catch (error) {
        return 'Essentially impossible';
    }
}

// ============================================================================
// PATTERN DETECTION (UNIQUENESS ANALYSIS)
// ============================================================================

/**
 * Detect keyboard patterns in password
 * Identifies common keyboard shortcuts and QWERTY sequences
 * 
 * @param {string} password - The password to analyze
 * @returns {Array} Array of detected keyboard patterns
 */
function detectKeyboardPatterns(password) {
    const patterns = [];
    const lowerPassword = password.toLowerCase();

    for (const pattern of KEYBOARD_PATTERNS) {
        if (lowerPassword.includes(pattern)) {
            patterns.push({
                type: 'keyboard',
                value: pattern,
                severity: 'high',
                description: `Keyboard pattern detected: "${pattern}"`
            });
        }
    }

    return patterns;
}

/**
 * Detect sequential characters in password
 * Identifies patterns like abc, 123, xyz, etc.
 * 
 * @param {string} password - The password to analyze
 * @returns {Array} Array of detected sequential patterns
 */
function detectSequentialPatterns(password) {
    const patterns = [];
    
    // Check for 3+ consecutive sequential characters
    for (let i = 0; i < password.length - 2; i++) {
        const char1Code = password.charCodeAt(i);
        const char2Code = password.charCodeAt(i + 1);
        const char3Code = password.charCodeAt(i + 2);

        // Check if characters are sequential (e.g., a→b→c or 1→2→3)
        if (char2Code === char1Code + 1 && char3Code === char2Code + 1) {
            const sequence = password.substring(i, i + 3);
            patterns.push({
                type: 'sequential',
                value: sequence,
                severity: 'medium',
                description: `Sequential pattern detected: "${sequence}"`
            });
            i += 2; // Skip ahead to avoid duplicate detections
        }
    }

    return patterns;
}

/**
 * Detect repeated characters in password
 * Identifies patterns like aaa, 1111, etc.
 * 
 * @param {string} password - The password to analyze
 * @returns {Array} Array of detected repetition patterns
 */
function detectRepeatedCharacters(password) {
    const patterns = [];
    const processed = new Set();
    
    // Check for 3+ identical consecutive characters
    for (let i = 0; i < password.length - 2; i++) {
        const char = password[i];
        
        // Skip if already processed
        if (processed.has(`${char}${i}`)) continue;

        if (password[i + 1] === char && password[i + 2] === char) {
            // Count total repetitions
            let count = 1;
            for (let j = i + 1; j < password.length && password[j] === char; j++) {
                count++;
            }
            
            patterns.push({
                type: 'repeated',
                value: char,
                count: count,
                severity: 'medium',
                description: `Character "${char}" repeated ${count} times`
            });
            
            // Mark as processed to avoid duplicates
            for (let j = 0; j < count; j++) {
                processed.add(`${char}${i + j}`);
            }
            
            i += count - 1;
        }
    }

    return patterns;
}

/**
 * Detect all patterns in password
 * Comprehensive pattern detection for uniqueness scoring
 * 
 * @param {string} password - The password to analyze
 * @returns {Array} All detected patterns
 */
export function detectPatterns(password) {
    if (!password) return [];
    
    const allPatterns = [
        ...detectKeyboardPatterns(password),
        ...detectSequentialPatterns(password),
        ...detectRepeatedCharacters(password)
    ];
    
    return allPatterns;
}

// ============================================================================
// DICTIONARY ATTACK DETECTION
// ============================================================================

/**
 * Check if password is in common password dictionary
 * Simulates detection of known breached passwords
 * 
 * @param {string} password - The password to check
 * @returns {boolean} True if password is in dictionary
 */
export function isCommonPassword(password) {
    return COMMON_PASSWORDS.includes(password.toLowerCase());
}

/**
 * Get dictionary risk level
 * Assesses vulnerability to dictionary attacks
 * 
 * @param {Array} patterns - Detected patterns array
 * @param {boolean} isCommon - Is password in dictionary
 * @returns {object} Risk assessment
 */
export function getDictionaryRisk(patterns, isCommon) {
    if (isCommon) {
        return {
            level: 'critical',
            label: 'CRITICAL',
            description: 'Password found in breach databases'
        };
    }
    
    if (patterns.length > 2) {
        return {
            level: 'moderate',
            label: 'Moderate',
            description: 'Multiple patterns detected'
        };
    }
    
    return {
        level: 'low',
        label: 'Low Risk',
        description: 'No obvious patterns detected'
    };
}

// ============================================================================
// UNIQUENESS SCORING
// ============================================================================

/**
 * Calculate uniqueness score (0-100)
 * Measures how random and non-repetitive the password is
 * 
 * Factors:
 * - Pattern detection (keyboard, sequential, repeated)
 * - Character variety
 * - Length
 * - Dictionary presence
 * 
 * @param {string} password - The password to score
 * @returns {number} Uniqueness score (0-100)
 */
export function calculateUniquenessScore(password) {
    if (!password) return 0;
    if (isCommonPassword(password)) return 0;

    let score = 100;
    const patterns = detectPatterns(password);
    
    // Penalty for each detected pattern
    score -= patterns.length * 15;
    
    // Check for character variety
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    
    const varietyCount = [hasLower, hasUpper, hasNumbers, hasSpecial].filter(Boolean).length;
    
    // Bonus for character variety
    score += varietyCount * 10;
    
    // Check for length
    if (password.length < 8) score -= 20;
    if (password.length < 12) score -= 10;
    if (password.length >= 16) score += 10;
    
    return Math.max(0, Math.min(100, score));
}

// ============================================================================
// OVERALL STRENGTH SCORING
// ============================================================================

/**
 * Calculate overall password strength score (0-100)
 * Combines entropy, uniqueness, requirements, and risk factors
 * 
 * @param {string} password - The password to score
 * @returns {number} Overall strength score (0-100)
 */
export function calculateStrengthScore(password) {
    if (!password) return 0;
    if (isCommonPassword(password)) return 0;

    const entropy = calculateEntropy(password);
    const length = password.length;
    const charPool = calculateCharPool(password);
    const uniqueness = calculateUniquenessScore(password);

    let score = 0;

    // Entropy contribution (0-40 points)
    // 128 bits is maximum entropy
    const entropyRatio = Math.min(1, entropy / 128);
    score += entropyRatio * 40;

    // Length contribution (0-20 points)
    if (length >= 12) score += 10;
    if (length >= 16) score += 5;
    if (length >= 20) score += 5;

    // Character variety contribution (0-20 points)
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    
    const varietyCount = [hasLower, hasUpper, hasNumbers, hasSpecial].filter(Boolean).length;
    score += varietyCount * 5;

    // Uniqueness contribution (0-20 points)
    score += (uniqueness / 100) * 20;

    return Math.max(0, Math.min(100, score));
}

// ============================================================================
// REQUIREMENT VALIDATION
// ============================================================================

/**
 * Validate password against all requirements
 * @param {string} password - The password to validate
 * @returns {object} Requirements met/failed
 */
export function validateRequirements(password) {
    return {
        length: password.length >= ANALYZER_CONFIG.MIN_PASSWORD_LENGTH,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        numbers: /[0-9]/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
        unique: detectPatterns(password).length === 0
    };
}

// ============================================================================
// STRENGTH CLASSIFICATION
// ============================================================================

/**
 * Get strength level and classification
 * @param {number} score - The strength score (0-100)
 * @returns {object} Strength classification
 */
export function getStrengthInfo(score) {
    if (score >= 80) {
        return {
            level: 'strong',
            label: 'STRONG',
            badge: 'badge-strong',
            color: 'strong',
            description: 'Excellent password strength'
        };
    } else if (score >= 50) {
        return {
            level: 'medium',
            label: 'MEDIUM',
            badge: 'badge-medium',
            color: 'medium',
            description: 'Moderate password strength'
        };
    } else {
        return {
            level: 'weak',
            label: 'WEAK',
            badge: 'badge-weak',
            color: 'weak',
            description: 'Poor password strength'
        };
    }
}

// ============================================================================
// REMEDIATION FEEDBACK GENERATION
// ============================================================================

/**
 * Generate personalized remediation feedback
 * Provides specific, actionable recommendations for improvement
 * 
 * @param {string} password - The password to provide feedback for
 * @param {number} entropy - Current entropy score
 * @returns {string} HTML remediation feedback
 */
export function generateRemediationFeedback(password, entropy) {
    if (!password) return '';
    
    const feedbacks = [];
    const patterns = detectPatterns(password);
    
    // Critical: Check for common password
    if (isCommonPassword(password)) {
        return '<strong style="color: #d32f2f;">CRITICAL:</strong> This password is widely known and appears in breach databases. Choose a completely unique password with no common words or sequences.';
    }

    // Check character variety
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

    if (!hasUpper) {
        feedbacks.push('Add uppercase letters (A-Z) to increase character pool size');
    }
    if (!hasNumbers) {
        feedbacks.push('Include numeric digits (0-9) for additional randomness');
    }
    if (!hasSpecial) {
        feedbacks.push('Add special characters (!@#$%^&*) to significantly boost entropy');
    }
    if (password.length < 16) {
        feedbacks.push('Increase length to 16+ characters for better brute-force resistance');
    }

    // Check for patterns
    if (patterns.length > 0) {
        feedbacks.push('Remove detected patterns: ' + patterns.map(p => `"${p.value}"`).join(', '));
    }

    // Check entropy
    if (entropy < 40) {
        feedbacks.push('Consider using random character combinations instead of dictionary words');
    }

    // No issues found
    if (feedbacks.length === 0) {
        return '<strong style="color: #1f8e79;">STRONG:</strong> Excellent password! No obvious improvements needed. This password demonstrates good entropy and resistance to common attacks.';
    }

    // Return formatted feedback
    const formattedFeedbacks = feedbacks
        .map((f, i) => `${i + 1}. ${f}`)
        .join('<br>');
    
    return `<strong style="color: #f57c00;">RECOMMENDATIONS:</strong><br>${formattedFeedbacks}`;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Format numbers with thousands separators
 * @param {number} num - Number to format
 * @returns {string} Formatted number
 */
export function formatNumber(num) {
    if (num > 1e15) {
        return num.toExponential(2);
    }
    return num.toLocaleString('en-US');
}

/**
 * Analyze complete password
 * Single function that performs all analysis and returns complete results
 * Used by main.js for comprehensive assessment
 * 
 * @param {string} password - The password to analyze
 * @returns {object} Complete analysis results
 */
export function analyzePassword(password) {
    if (!password) {
        return {
            password: '',
            entropy: 0,
            score: 0,
            charPool: 0,
            combinations: 0,
            crackTime: 'Instant',
            patterns: [],
            isCommon: false,
            uniqueness: 0,
            requirements: {
                length: false,
                uppercase: false,
                lowercase: false,
                numbers: false,
                special: false,
                unique: false
            },
            strengthInfo: {
                level: 'weak',
                label: 'WEAK',
                badge: 'badge-weak',
                color: 'weak',
                description: 'No password entered'
            },
            remediation: '',
            dictionaryRisk: {
                level: 'low',
                label: '✅ Low Risk',
                description: 'No password to assess'
            }
        };
    }

    const entropy = calculateEntropy(password);
    const charPool = calculateCharPool(password);
    const combinations = calculateCombinations(password);
    const crackTime = calculateCrackTime(entropy);
    const patterns = detectPatterns(password);
    const isCommon = isCommonPassword(password);
    const uniqueness = calculateUniquenessScore(password);
    const score = calculateStrengthScore(password);
    const requirements = validateRequirements(password);
    const strengthInfo = getStrengthInfo(score);
    const remediation = generateRemediationFeedback(password, entropy);
    const dictionaryRisk = getDictionaryRisk(patterns, isCommon);

    return {
        password,
        entropy: Math.round(entropy * 100) / 100,
        score: Math.round(score),
        charPool,
        combinations,
        crackTime,
        patterns,
        isCommon,
        uniqueness: Math.round(uniqueness),
        requirements,
        strengthInfo,
        remediation,
        dictionaryRisk
    };
}
