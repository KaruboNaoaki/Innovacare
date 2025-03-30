/**
 * Form validation utilities for the Healthcare Data Management System
 */

// DOM ready function
document.addEventListener('DOMContentLoaded', function() {
    // Add validation to all forms with the 'needs-validation' class
    const forms = document.querySelectorAll('.needs-validation');
    if (forms) {
        Array.from(forms).forEach(function(form) {
            form.addEventListener('submit', function(event) {
                if (!form.checkValidity()) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                
                form.classList.add('was-validated');
            }, false);
        });
    }
    
    // Password validation
    const passwordInputs = document.querySelectorAll('input[type="password"][data-validate="true"]');
    if (passwordInputs) {
        passwordInputs.forEach(function(input) {
            // Add strength meter after input
            const strengthMeterHtml = `
                <div class="password-strength-meter mt-2">
                    <div class="progress" style="height: 5px;">
                        <div class="progress-bar bg-danger" role="progressbar" style="width: 0%" 
                             id="strength-meter-${input.id}" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
                    </div>
                    <div class="d-flex justify-content-between mt-1">
                        <small class="text-muted">Password Strength:</small>
                        <small id="strength-text-${input.id}" class="text-danger">Weak</small>
                    </div>
                </div>
            `;
            
            input.insertAdjacentHTML('afterend', strengthMeterHtml);
            
            // Monitor password input
            input.addEventListener('input', function() {
                const strength = checkPasswordStrength(input.value);
                updatePasswordStrengthUI(
                    `strength-meter-${input.id}`, 
                    `strength-text-${input.id}`, 
                    strength
                );
            });
        });
    }
    
    // Password confirmation validation
    const confirmPasswordInputs = document.querySelectorAll('input[data-match-password]');
    if (confirmPasswordInputs) {
        confirmPasswordInputs.forEach(function(input) {
            const originalPasswordId = input.getAttribute('data-match-password');
            const originalPassword = document.getElementById(originalPasswordId);
            
            if (originalPassword) {
                // Validate on input change
                input.addEventListener('input', function() {
                    validatePasswordMatch(originalPassword, input);
                });
                
                originalPassword.addEventListener('input', function() {
                    if (input.value) {
                        validatePasswordMatch(originalPassword, input);
                    }
                });
            }
        });
    }
    
    // Date validation (ensure dates are not in the future)
    const pastDateInputs = document.querySelectorAll('input[type="date"][data-past-only="true"]');
    if (pastDateInputs) {
        pastDateInputs.forEach(function(input) {
            // Set max attribute to today
            const today = new Date().toISOString().split('T')[0];
            input.setAttribute('max', today);
            
            // Validate on change
            input.addEventListener('change', function() {
                const selectedDate = new Date(input.value);
                const currentDate = new Date();
                
                if (selectedDate > currentDate) {
                    input.setCustomValidity('Date cannot be in the future');
                } else {
                    input.setCustomValidity('');
                }
            });
        });
    }
    
    // Phone number validation
    const phoneInputs = document.querySelectorAll('input[type="tel"]');
    if (phoneInputs) {
        phoneInputs.forEach(function(input) {
            input.addEventListener('input', function() {
                // Format as user types
                const x = input.value.replace(/\D/g, '').match(/(\d{0,3})(\d{0,3})(\d{0,4})/);
                input.value = !x[2] ? x[1] : x[1] + '-' + x[2] + (x[3] ? '-' + x[3] : '');
                
                // Validate format
                const regex = /^\d{3}-\d{3}-\d{4}$/;
                if (input.value && !regex.test(input.value)) {
                    input.setCustomValidity('Please enter a valid phone number in the format 123-456-7890');
                } else {
                    input.setCustomValidity('');
                }
            });
        });
    }
});

/**
 * Check password strength (0-6 scale)
 * @param {string} password - Password to check
 * @return {number} Strength score from 0-6
 */
function checkPasswordStrength(password) {
    if (!password) return 0;
    
    let strength = 0;
    
    // Length check
    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    
    // Character type checks
    if (password.match(/[a-z]+/)) strength += 1;
    if (password.match(/[A-Z]+/)) strength += 1;
    if (password.match(/[0-9]+/)) strength += 1;
    if (password.match(/[^a-zA-Z0-9]+/)) strength += 1;
    
    return strength;
}

/**
 * Update the password strength UI elements
 * @param {string} meterId - ID of the progress bar element
 * @param {string} textId - ID of the text description element
 * @param {number} strength - Strength value (0-6)
 */
function updatePasswordStrengthUI(meterId, textId, strength) {
    const meter = document.getElementById(meterId);
    const text = document.getElementById(textId);
    
    if (!meter || !text) return;
    
    // Update meter width
    meter.style.width = (strength / 6 * 100) + '%';
    
    // Update meter color and text
    if (strength < 2) {
        meter.className = 'progress-bar bg-danger';
        text.textContent = 'Weak';
        text.className = 'text-danger';
    } else if (strength < 4) {
        meter.className = 'progress-bar bg-warning';
        text.textContent = 'Fair';
        text.className = 'text-warning';
    } else {
        meter.className = 'progress-bar bg-success';
        text.textContent = 'Strong';
        text.className = 'text-success';
    }
}

/**
 * Validate that confirmation password matches original password
 * @param {HTMLElement} passwordInput - Original password input
 * @param {HTMLElement} confirmInput - Confirmation password input
 */
function validatePasswordMatch(passwordInput, confirmInput) {
    if (passwordInput.value !== confirmInput.value) {
        confirmInput.setCustomValidity('Passwords do not match');
    } else {
        confirmInput.setCustomValidity('');
    }
}

/**
 * Validate an email address format
 * @param {string} email - Email address to validate
 * @return {boolean} True if email is valid
 */
function validateEmail(email) {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

/**
 * Validate a date of birth (must be in the past and reasonable)
 * @param {string} dob - Date of birth in YYYY-MM-DD format
 * @return {boolean} True if date is valid
 */
function validateDateOfBirth(dob) {
    const dobDate = new Date(dob);
    const today = new Date();
    
    // Must be in the past
    if (dobDate >= today) return false;
    
    // Check if date is reasonable (not more than 120 years ago)
    const maxAge = new Date();
    maxAge.setFullYear(today.getFullYear() - 120);
    if (dobDate < maxAge) return false;
    
    return true;
}

/**
 * Validate entire form and show appropriate error messages
 * @param {string} formId - ID of the form to validate
 * @return {boolean} True if form is valid
 */
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    // Trigger HTML5 validation
    if (!form.checkValidity()) {
        form.classList.add('was-validated');
        return false;
    }
    
    // Perform custom validations here if needed
    
    return true;
}
