/**
 * Main JavaScript file for the Healthcare Data Management System
 */

// DOM ready function
document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert:not(.alert-persistent)');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Password show/hide toggle
    const togglePassword = document.querySelectorAll('.toggle-password');
    if (togglePassword) {
        togglePassword.forEach(function(button) {
            button.addEventListener('click', function() {
                const input = document.querySelector(button.getAttribute('data-target'));
                if (input.type === 'password') {
                    input.type = 'text';
                    button.innerHTML = '<i class="fas fa-eye-slash"></i>';
                } else {
                    input.type = 'password';
                    button.innerHTML = '<i class="fas fa-eye"></i>';
                }
            });
        });
    }
    
    // Initialize tooltips
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltips.length > 0) {
        tooltips.forEach(function(tooltip) {
            new bootstrap.Tooltip(tooltip);
        });
    }
    
    // Initialize popovers
    const popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
    if (popovers.length > 0) {
        popovers.forEach(function(popover) {
            new bootstrap.Popover(popover);
        });
    }
    
    // Patient search functionality
    const patientSearch = document.getElementById('patientSearch');
    if (patientSearch) {
        patientSearch.addEventListener('keyup', function() {
            const searchValue = this.value.toLowerCase();
            const patientRows = document.querySelectorAll('#patientsTable tbody tr');
            
            patientRows.forEach(function(row) {
                const rowText = row.textContent.toLowerCase();
                if (rowText.includes(searchValue)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }
    
    // Confirm delete actions
    const deleteButtons = document.querySelectorAll('.btn-delete-confirm');
    if (deleteButtons) {
        deleteButtons.forEach(function(button) {
            button.addEventListener('click', function(e) {
                if (!confirm('Are you sure you want to delete this item? This action cannot be undone.')) {
                    e.preventDefault();
                }
            });
        });
    }
    
    // Phone number formatting
    const phoneInputs = document.querySelectorAll('input[type="tel"]');
    if (phoneInputs) {
        phoneInputs.forEach(function(input) {
            input.addEventListener('input', function(e) {
                const x = e.target.value.replace(/\D/g, '').match(/(\d{0,3})(\d{0,3})(\d{0,4})/);
                e.target.value = !x[2] ? x[1] : x[1] + '-' + x[2] + (x[3] ? '-' + x[3] : '');
            });
        });
    }
    
    // Session timeout warning
    let sessionTimeoutWarning = 55 * 60 * 1000; // 55 minutes
    let sessionTimeout = 60 * 60 * 1000; // 60 minutes
    let warningTimer;
    let timeoutTimer;
    
    function startSessionTimers() {
        warningTimer = setTimeout(function() {
            // Show warning modal
            const warningModal = new bootstrap.Modal(document.getElementById('sessionWarningModal'));
            if (warningModal) {
                warningModal.show();
            } else {
                alert('Your session is about to expire due to inactivity. Please save your work and refresh the page.');
            }
        }, sessionTimeoutWarning);
        
        timeoutTimer = setTimeout(function() {
            // Redirect to logout
            window.location.href = '/logout';
        }, sessionTimeout);
    }
    
    function resetSessionTimers() {
        clearTimeout(warningTimer);
        clearTimeout(timeoutTimer);
        startSessionTimers();
    }
    
    // Start timers
    startSessionTimers();
    
    // Reset timers on user activity
    document.addEventListener('click', resetSessionTimers);
    document.addEventListener('keypress', resetSessionTimers);
    document.addEventListener('scroll', resetSessionTimers);
    document.addEventListener('mousemove', resetSessionTimers);
    
    // Continue session button
    const continueSessionBtn = document.getElementById('continueSessionBtn');
    if (continueSessionBtn) {
        continueSessionBtn.addEventListener('click', function() {
            resetSessionTimers();
            const warningModal = bootstrap.Modal.getInstance(document.getElementById('sessionWarningModal'));
            warningModal.hide();
        });
    }
});

// Flash message function
function showFlashMessage(message, type = 'info') {
    const alertContainer = document.getElementById('alert-container');
    if (!alertContainer) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.appendChild(alert);
    
    setTimeout(function() {
        const bsAlert = new bootstrap.Alert(alert);
        bsAlert.close();
    }, 5000);
}

// Form validation function
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    if (!form.checkValidity()) {
        form.classList.add('was-validated');
        return false;
    }
    
    return true;
}

// HIPAA compliance notice acceptance
function acceptHIPAANotice() {
    localStorage.setItem('hipaaNoticeAccepted', 'true');
    const hipaaModal = bootstrap.Modal.getInstance(document.getElementById('hipaaNoticeModal'));
    if (hipaaModal) {
        hipaaModal.hide();
    }
}

// Check if HIPAA notice has been accepted
function checkHIPAANotice() {
    const accepted = localStorage.getItem('hipaaNoticeAccepted');
    if (!accepted) {
        const hipaaModal = new bootstrap.Modal(document.getElementById('hipaaNoticeModal'));
        if (hipaaModal) {
            hipaaModal.show();
        }
    }
}

// Password strength meter
function checkPasswordStrength(password) {
    let strength = 0;
    
    // Length check
    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    
    // Character type checks
    if (password.match(/[a-z]+/)) strength += 1;
    if (password.match(/[A-Z]+/)) strength += 1;
    if (password.match(/[0-9]+/)) strength += 1;
    if (password.match(/[^a-zA-Z0-9]+/)) strength += 1;
    
    // Return strength level (0-6)
    return strength;
}

// Update password strength indicator
function updatePasswordStrength(passwordInput, strengthMeter, strengthText) {
    const input = document.getElementById(passwordInput);
    const meter = document.getElementById(strengthMeter);
    const text = document.getElementById(strengthText);
    
    if (!input || !meter || !text) return;
    
    const strength = checkPasswordStrength(input.value);
    
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
