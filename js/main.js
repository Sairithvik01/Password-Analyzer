/* ============================================================================
   MAIN ORCHESTRATOR MODULE
   ============================================================================
   Central orchestrator that manages:
   - DOM event listeners
   - UI state and updates
   - LocalStorage-based password history database
   - Module coordination between analyzer and generator
   - Real-time password analysis
   ========================================================================== */

import * as Analyzer from './analyzer.js';
import * as Generator from './generator.js';

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

const UI_SELECTORS = {
    // Input
    passwordInput: '#passwordInput',
    toggleVisibilityBtn: '#toggleVisibilityBtn',
    clearBtn: '#clearBtn',
    generateBtn: '#generateBtn',
    
    // Display
    strengthBadge: '#strengthBadge',
    scorePercentage: '#scorePercentage',
    scoreDescription: '#scoreDescription',
    
    // Metrics
    entropyValue: '#entropyValue',
    entropyProgress: '#entropyProgress',
    uniquenessValue: '#uniquenessValue',
    uniquenessProgress: '#uniquenessProgress',
    poolValue: '#poolValue',
    combinationsValue: '#combinationsValue',
    crackTimeValue: '#crackTimeValue',
    dictionaryRisk: '#dictionaryRisk',
    
    // Requirements
    requirementsPrefix: '#req-',
    
    // Pattern Detection
    patternResults: '#patternResults',
    
    // Remediation
    remediationSection: '#remediationSection',
    remediationText: '#remediationText',
    
    // Alternatives
    alternativesContainer: '#alternativesContainer',
    
    // History/Profile
    profileUsername: '#profileUsername',
    profileLastCheck: '#profileLastCheck',
    profileHistoryCount: '#profileHistoryCount',
    clearHistoryBtn: '#clearHistoryBtn',
    historyWarning: '#historyWarning',
    
    // Tabs/Navigation
    cryptoBtn: '#cryptoBtn',
    aboutBtn: '#aboutBtn',
    cryptoModal: '#cryptoModal',
    aboutModal: '#aboutModal'
};

const EYE_OPEN_ICON = `
    <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
        <path d="M2.25 12s3.5-6.5 9.75-6.5S21.75 12 21.75 12s-3.5 6.5-9.75 6.5S2.25 12 2.25 12Z"></path>
        <circle cx="12" cy="12" r="3"></circle>
    </svg>
`;

const EYE_CLOSED_ICON = `
    <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
        <path d="M3 3l18 18"></path>
        <path d="M10.6 10.6A2.9 2.9 0 0 0 12 15a3 3 0 0 0 2.4-1.2"></path>
        <path d="M6.5 6.9C3.8 8.8 2.25 12 2.25 12s3.5 6.5 9.75 6.5c1.7 0 3.2-.48 4.45-1.16"></path>
        <path d="M9.8 5.7A9.5 9.5 0 0 1 12 5.5c6.25 0 9.75 6.5 9.75 6.5a17.2 17.2 0 0 1-2.3 3.02"></path>
    </svg>
`;

const STORAGE_KEYS = {
    passwordHistory: 'pf_password_history',
    lastAssessment: 'pf_last_assessment',
    userName: 'pf_username'
};

// ============================================================================
// PASSWORD HISTORY DATABASE (LocalStorage-Based)
// ============================================================================

class PasswordHistoryDB {
    /**
     * Initialize password history database
     */
    constructor() {
        this.initializeStorage();
    }

    /**
     * Initialize storage with default values if needed
     */
    initializeStorage() {
        if (!localStorage.getItem(STORAGE_KEYS.passwordHistory)) {
            localStorage.setItem(STORAGE_KEYS.passwordHistory, JSON.stringify([]));
        }
        if (!localStorage.getItem(STORAGE_KEYS.userName)) {
            localStorage.setItem(STORAGE_KEYS.userName, 'intern_dev_2024');
        }
        if (!localStorage.getItem(STORAGE_KEYS.lastAssessment)) {
            localStorage.setItem(STORAGE_KEYS.lastAssessment, 'Never');
        }
    }

    /**
     * Get all stored password hashes (simplified - just store lowercased versions)
     * In production, these would be properly salted and hashed with bcrypt/Argon2
     * 
     * @returns {Array} Array of previously used passwords
     */
    getHistory() {
        try {
            const history = localStorage.getItem(STORAGE_KEYS.passwordHistory);
            return history ? JSON.parse(history) : [];
        } catch (e) {
            console.error('Error reading password history:', e);
            return [];
        }
    }

    /**
     * Check if password was previously used
     * Compares against stored history
     * 
     * @param {string} password - Password to check
     * @returns {boolean} True if password was previously used
     */
    wasUsedBefore(password) {
        if (!password) return false;
        const history = this.getHistory();
        // In production, you'd compare proper password hashes
        // For demo, we compare the password itself
        return history.includes(password.toLowerCase());
    }

    /**
     * Add password to history
     * Called when user confirms/saves a new password
     * 
     * @param {string} password - Password to add to history
     */
    addToHistory(password) {
        if (!password) return;
        
        const history = this.getHistory();
        
        // Prevent duplicate entries
        if (!history.includes(password.toLowerCase())) {
            history.push(password.toLowerCase());
            
            // Keep only last 10 passwords (limit storage)
            if (history.length > 10) {
                history.shift();
            }
            
            localStorage.setItem(STORAGE_KEYS.passwordHistory, JSON.stringify(history));
            this.updateLastAssessment();
        }
    }

    /**
     * Clear all password history
     * Used for testing and user preference
     */
    clearHistory() {
        localStorage.setItem(STORAGE_KEYS.passwordHistory, JSON.stringify([]));
        this.updateLastAssessment();
    }

    /**
     * Update last assessment timestamp
     */
    updateLastAssessment() {
        const now = new Date().toLocaleString();
        localStorage.setItem(STORAGE_KEYS.lastAssessment, now);
    }

    /**
     * Get last assessment time
     */
    getLastAssessment() {
        return localStorage.getItem(STORAGE_KEYS.lastAssessment) || 'Never';
    }

    /**
     * Get username
     */
    getUsername() {
        return localStorage.getItem(STORAGE_KEYS.userName) || 'intern_dev_2024';
    }
}

// ============================================================================
// UI STATE MANAGER
// ============================================================================

class UIManager {
    /**
     * Initialize UI manager with DOM selectors and DB instance
     */
    constructor(db) {
        this.db = db;
        this.currentAnalysis = null;
        this.passwordInputElement = document.querySelector(UI_SELECTORS.passwordInput);
        this.updateProfileDisplay();
    }

    /**
     * Update password analysis display with current results
     * Called on every keystroke in password input
     */
    updateAnalysisDisplay(analysis) {
        this.currentAnalysis = analysis;
        
        // Update strength badge and score
        const badge = document.querySelector(UI_SELECTORS.strengthBadge);
        badge.textContent = analysis.strengthInfo.label;
        badge.className = `strength-badge ${analysis.strengthInfo.badge}`;
        
        // Update score percentage
        document.querySelector(UI_SELECTORS.scorePercentage).textContent = analysis.score;
        document.querySelector(UI_SELECTORS.scoreDescription).textContent = 
            analysis.strengthInfo.description;
        
        // Update entropy metrics
        document.querySelector(UI_SELECTORS.entropyValue).textContent = 
            `${analysis.entropy.toFixed(2)} bits`;
        document.querySelector(UI_SELECTORS.entropyProgress).style.width = 
            `${Math.min(100, (analysis.entropy / 128) * 100)}%`;
        document.querySelector(UI_SELECTORS.entropyProgress).className = 
            `progress-fill ${analysis.strengthInfo.color}`;
        
        // Update uniqueness metrics
        document.querySelector(UI_SELECTORS.uniquenessValue).textContent = 
            `${analysis.uniqueness}/100`;
        document.querySelector(UI_SELECTORS.uniquenessProgress).style.width = 
            `${analysis.uniqueness}%`;
        document.querySelector(UI_SELECTORS.uniquenessProgress).className = 
            `progress-fill ${analysis.strengthInfo.color}`;
        
        // Update security metrics
        document.querySelector(UI_SELECTORS.poolValue).textContent = 
            Analyzer.formatNumber(analysis.charPool);
        document.querySelector(UI_SELECTORS.combinationsValue).textContent = 
            Analyzer.formatNumber(analysis.combinations);
        document.querySelector(UI_SELECTORS.crackTimeValue).textContent = 
            analysis.crackTime;
        
        // Update dictionary risk
        const dictionaryEl = document.querySelector(UI_SELECTORS.dictionaryRisk);
        dictionaryEl.textContent = analysis.dictionaryRisk.label;
        dictionaryEl.style.color = this.getRiskColor(analysis.dictionaryRisk.level);
        
        // Update requirements checklist
        this.updateRequirementsDisplay(analysis.requirements);
        
        // Update pattern detection
        this.updatePatternDisplay(analysis.patterns, analysis.isCommon);
        
        // Update remediation feedback
        if (analysis.score < 80) {
            document.querySelector(UI_SELECTORS.remediationSection).style.display = 'block';
            document.querySelector(UI_SELECTORS.remediationText).innerHTML = analysis.remediation;
        } else {
            document.querySelector(UI_SELECTORS.remediationSection).style.display = 'none';
        }
        
        // Generate and display alternatives
        this.updateAlternativesDisplay(analysis);
        
        // Check password history
        this.updatePasswordHistoryWarning(analysis.password);
    }

    /**
     * Update requirements checklist display
     */
    updateRequirementsDisplay(requirements) {
        const requirementsList = [
            {key: 'length', id: 'length'},
            {key: 'uppercase', id: 'upper'},
            {key: 'lowercase', id: 'lower'},
            {key: 'numbers', id: 'number'},
            {key: 'special', id: 'special'},
            {key: 'unique', id: 'unique'}
        ];

        requirementsList.forEach(req => {
            const element = document.querySelector(`${UI_SELECTORS.requirementsPrefix}${req.id}`);
            const isMet = requirements[req.key];
            
            if (isMet) {
                element.classList.add('met');
                element.querySelector('.check-icon').textContent = '✓';
            } else {
                element.classList.remove('met');
                element.querySelector('.check-icon').textContent = '○';
            }
        });
    }

    /**
     * Update pattern detection display
     */
    updatePatternDisplay(patterns, isCommon) {
        const container = document.querySelector(UI_SELECTORS.patternResults);
        
        if (isCommon) {
            container.innerHTML = `
                <div class="pattern-item danger">
                    <strong>Dictionary Match</strong><br>
                    This password appears in known breach databases and will be cracked instantly.
                </div>
            `;
            return;
        }

        if (patterns.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 20px; color: #5f6368;">
                    No suspicious patterns detected!
                </div>
            `;
            return;
        }

        let html = '';
        for (const pattern of patterns) {
            const severity = pattern.severity === 'high' ? 'danger' : 'warning';
            html += `
                <div class="pattern-item ${severity}">
                    <strong>${pattern.severity === 'high' ? 'Alert' : 'Pattern'}: ${pattern.type}</strong><br>
                    <span>${pattern.description}</span>
                </div>
            `;
        }
        container.innerHTML = html;
    }

    /**
     * Generate and display password alternatives
     */
    updateAlternativesDisplay(analysis) {
        const container = document.querySelector(UI_SELECTORS.alternativesContainer);
        
        // Only show alternatives if password is weak or medium
        if (analysis.score >= 80) {
            container.innerHTML = '<p class="empty-state">Strong password! No alternatives needed.</p>';
            return;
        }

        // Generate 3 hardened alternatives
        const alternatives = Generator.generateHardenedAlternatives(analysis);
        
        let html = '';
        for (const alt of alternatives) {
            const altAnalysis = Analyzer.analyzePassword(alt);
            const strengthLabel = altAnalysis.score >= 80 ? 'Strong' : altAnalysis.score >= 50 ? 'Medium' : 'Weak';
            
            html += `
                <div class="alternative-password">
                    <div>
                        <div class="password-text">${this.escapeHtml(alt)}</div>
                        <div class="password-score">
                            ${strengthLabel} | Score: ${altAnalysis.score}% • Entropy: ${altAnalysis.entropy.toFixed(1)} bits
                        </div>
                    </div>
                    <button class="copy-button" onclick="copyPasswordToClipboard('${this.escapeHtml(alt)}', this)">
                        Copy
                    </button>
                </div>
            `;
        }
        container.innerHTML = html;
    }

    /**
     * Update password history warning
     */
    updatePasswordHistoryWarning(password) {
        const warningEl = document.querySelector(UI_SELECTORS.historyWarning);
        const wasUsedBefore = this.db.wasUsedBefore(password);
        
        if (wasUsedBefore && password) {
            warningEl.style.display = 'block';
        } else {
            warningEl.style.display = 'none';
        }
    }

    /**
     * Update profile display
     */
    updateProfileDisplay() {
        const username = this.db.getUsername();
        const lastCheck = this.db.getLastAssessment();
        const history = this.db.getHistory();
        
        document.querySelector(UI_SELECTORS.profileUsername).textContent = username;
        document.querySelector(UI_SELECTORS.profileLastCheck).textContent = lastCheck;
        document.querySelector(UI_SELECTORS.profileHistoryCount).textContent = history.length;
    }

    /**
     * Reset display to initial state
     */
    resetDisplay() {
        document.querySelector(UI_SELECTORS.strengthBadge).textContent = 'No Password';
        document.querySelector(UI_SELECTORS.strengthBadge).className = 'strength-badge badge-weak';
        document.querySelector(UI_SELECTORS.scorePercentage).textContent = '0';
        document.querySelector(UI_SELECTORS.scoreDescription).textContent = 'Enter a password to begin analysis';
        
        document.querySelector(UI_SELECTORS.entropyValue).textContent = '0.00 bits';
        document.querySelector(UI_SELECTORS.entropyProgress).style.width = '0%';
        document.querySelector(UI_SELECTORS.uniquenessValue).textContent = '0/100';
        document.querySelector(UI_SELECTORS.uniquenessProgress).style.width = '0%';
        
        document.querySelector(UI_SELECTORS.poolValue).textContent = '0';
        document.querySelector(UI_SELECTORS.combinationsValue).textContent = '0';
        document.querySelector(UI_SELECTORS.crackTimeValue).textContent = 'Instant';
        
        // Reset requirements
        document.querySelectorAll('[id^="req-"]').forEach(el => {
            el.classList.remove('met');
            el.querySelector('.check-icon').textContent = '○';
        });
        
        document.querySelector(UI_SELECTORS.patternResults).innerHTML = 
            '<p class="empty-state">Enter a password to scan for patterns...</p>';
        document.querySelector(UI_SELECTORS.remediationSection).style.display = 'none';
        document.querySelector(UI_SELECTORS.alternativesContainer).innerHTML = 
            '<p class="empty-state">Generate alternatives to strengthen your password</p>';
        document.querySelector(UI_SELECTORS.historyWarning).style.display = 'none';
    }

    /**
     * Get color for risk level
     */
    getRiskColor(level) {
        switch(level) {
            case 'critical': return '#d32f2f';
            case 'moderate': return '#f57c00';
            case 'low': return '#1f8e79';
            default: return '#5f6368';
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

/**
 * Initialize event listeners
 */
function initializeEventListeners(uiManager, db) {
    const passwordInput = document.querySelector(UI_SELECTORS.passwordInput);
    const visibilityBtn = document.querySelector(UI_SELECTORS.toggleVisibilityBtn);
    const visibilityIcon = visibilityBtn.querySelector('.eye-icon');

    const setPasswordVisibility = (isVisible) => {
        passwordInput.type = isVisible ? 'text' : 'password';
        visibilityBtn.setAttribute('aria-pressed', String(isVisible));
        visibilityBtn.setAttribute('aria-label', isVisible ? 'Hide password' : 'Show password');
        visibilityBtn.setAttribute('title', isVisible ? 'Hide password' : 'Show password');
        visibilityIcon.innerHTML = isVisible ? EYE_CLOSED_ICON : EYE_OPEN_ICON;
    };

    const openModal = (selector) => {
        const modal = document.querySelector(selector);
        if (!modal) return;
        modal.style.display = 'flex';
        const closeButton = modal.querySelector('[data-modal-close]');
        if (closeButton) closeButton.focus();
    };

    const closeModal = (modal) => {
        if (!modal) return;
        modal.style.display = 'none';
        document.querySelectorAll('.nav-button').forEach(btn => btn.classList.remove('active'));
    };

    setPasswordVisibility(false);
    
    // Real-time password analysis
    passwordInput.addEventListener('input', (e) => {
        const password = e.target.value;
        
        if (!password) {
            uiManager.resetDisplay();
            return;
        }
        
        // Perform full analysis
        const analysis = Analyzer.analyzePassword(password);
        uiManager.updateAnalysisDisplay(analysis);
    });

    // Toggle password visibility
    visibilityBtn.addEventListener('click', () => {
        setPasswordVisibility(passwordInput.type === 'password');
    });

    // Clear password
    document.querySelector(UI_SELECTORS.clearBtn).addEventListener('click', () => {
        passwordInput.value = '';
        passwordInput.focus();
        uiManager.resetDisplay();
    });

    // Generate strong password
    document.querySelector(UI_SELECTORS.generateBtn).addEventListener('click', () => {
        const generated = Generator.generateSecurePassword(16);
        passwordInput.value = generated;
        setPasswordVisibility(true);
        
        // Trigger analysis
        const event = new Event('input', {bubbles: true});
        passwordInput.dispatchEvent(event);
    });

    // Clear history button
    document.querySelector(UI_SELECTORS.clearHistoryBtn).addEventListener('click', () => {
        if (confirm('Clear all password history? This action cannot be undone.')) {
            db.clearHistory();
            uiManager.updateProfileDisplay();
            uiManager.resetDisplay();
        }
    });

    // Navigation buttons
    document.querySelector(UI_SELECTORS.cryptoBtn).addEventListener('click', (e) => {
        document.querySelectorAll('.nav-button').forEach(btn => btn.classList.remove('active'));
        e.currentTarget.classList.add('active');
        openModal(UI_SELECTORS.cryptoModal);
    });

    document.querySelector(UI_SELECTORS.aboutBtn).addEventListener('click', (e) => {
        document.querySelectorAll('.nav-button').forEach(btn => btn.classList.remove('active'));
        e.currentTarget.classList.add('active');
        openModal(UI_SELECTORS.aboutModal);
    });

    // Modal close buttons
    document.querySelectorAll('[data-modal-close]').forEach((modalClose) => {
        modalClose.addEventListener('click', () => {
            closeModal(modalClose.closest('.modal'));
        });
    });

    // Close modal when clicking outside
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            closeModal(e.target);
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        document.querySelectorAll('.modal').forEach((modal) => {
            if (modal.style.display !== 'none') closeModal(modal);
        });
    });
}

// ============================================================================
// UTILITY FUNCTIONS (Global)
// ============================================================================

/**
 * Copy password to clipboard
 * Global function for button onclick handlers
 */
window.copyPasswordToClipboard = function(password, button) {
    navigator.clipboard.writeText(password).then(() => {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('copied');
        
        setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('copied');
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy password:', err);
    });
};

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initialize the entire application
 * Called when DOM is ready
 */
function initializeApp() {
    console.log('🔐 Password Fortress initializing...');
    
    // Initialize database
    const db = new PasswordHistoryDB();
    
    // Initialize UI manager
    const uiManager = new UIManager(db);
    
    // Initialize event listeners
    initializeEventListeners(uiManager, db);
    
    // Set initial focus
    document.querySelector(UI_SELECTORS.passwordInput).focus();
    
    console.log('✅ Password Fortress ready');
}

// ============================================================================
// STARTUP
// ============================================================================

// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}
