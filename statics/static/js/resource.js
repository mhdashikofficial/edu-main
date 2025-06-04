// All the code is wrapped in DOMContentLoaded to ensure the DOM is ready
// and uses event delegation for dynamic elements (edit/delete buttons)
document.addEventListener('DOMContentLoaded', function() {
    // Check if this is a premium resource
    const isPremium = document.querySelector('.badge.bg-primary') !== null;
    
    if (isPremium) {
        // Check purchase status from the page data or make an API call
        const resourceId = window.location.pathname.split('/')[2];
        checkPurchaseStatus(resourceId);
        
        // If purchase was just completed (from URL parameter)
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('purchased') && urlParams.get('purchased') === 'true') {
            hidePurchaseButton();
            showSuccessMessage();
        }
    }
    
    // Handle purchase button click
    const purchaseBtn = document.getElementById('purchase-btn');
    if (purchaseBtn) {
        purchaseBtn.addEventListener('click', function(e) {
            e.preventDefault();
            makePurchase(this.href);
        });
    }
});

function checkPurchaseStatus(resourceId) {
    // Make an AJAX call to check purchase status
    fetch(`/api/resource/${resourceId}/purchase-status`, {
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        },
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.has_purchased) {
            hidePurchaseButton();
            showSuccessMessage();
        }
    })
    .catch(error => {
        console.error('Error checking purchase status:', error);
    });
}

function hidePurchaseButton() {
    const purchaseBtn = document.querySelector('.btn-purchase');
    const previewAlert = document.querySelector('.preview-alert');
    
    if (purchaseBtn) {
        purchaseBtn.style.display = 'none';
    }
    
    if (previewAlert) {
        previewAlert.style.display = 'none';
    }
    
    // Show access granted message
    const accessMessage = document.querySelector('.access-message');
    if (accessMessage) {
        accessMessage.style.display = 'block';
    }
}

function showSuccessMessage() {
    const successAlert = document.createElement('div');
    successAlert.className = 'alert alert-success mt-3';
    successAlert.innerHTML = `
        <i class="fas fa-check-circle me-2"></i>
        You have successfully purchased this resource. Full content is now available.
    `;
    
    const cardBody = document.querySelector('.card-body');
    if (cardBody) {
        cardBody.insertBefore(successAlert, cardBody.firstChild);
    }
}

function makePurchase(url) {
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        },
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            hidePurchaseButton();
            showSuccessMessage();
            
            // Update the UI to show full content
            if (data.resource_content) {
                document.querySelector('.resource-content').innerHTML = data.resource_content;
            }
            
            // Update download button if exists
            const downloadBtn = document.querySelector('.download-btn');
            if (downloadBtn) {
                downloadBtn.classList.remove('disabled');
                downloadBtn.removeAttribute('disabled');
            }
        } else {
            showError(data.message || 'Purchase failed. Please try again.');
        }
    })
    .catch(error => {
        console.error('Purchase error:', error);
        showError('An error occurred during purchase. Please try again.');
    });
}

function showError(message) {
    const errorAlert = document.createElement('div');
    errorAlert.className = 'alert alert-danger mt-3';
    errorAlert.innerHTML = `
        <i class="fas fa-exclamation-circle me-2"></i>
        ${message}
    `;
    
    const cardBody = document.querySelector('.card-body');
    if (cardBody) {
        cardBody.insertBefore(errorAlert, cardBody.firstChild);
    }
}

function getCSRFToken() {
    const csrfToken = document.querySelector('meta[name="csrf-token"]');
    return csrfToken ? csrfToken.getAttribute('content') : '';
}

// If using real-time updates (like Socket.IO)
if (typeof io !== 'undefined') {
    const socket = io();
    
    socket.on('purchase_update', function(data) {
        if (data.resource_id === window.location.pathname.split('/')[2]) {
            hidePurchaseButton();
            showSuccessMessage();
        }
    });
}