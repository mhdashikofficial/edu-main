document.addEventListener('DOMContentLoaded', function() {
    // Initialize datetime picker for meeting creation
    if (document.getElementById('scheduled_time')) {
        $('#scheduled_time').datetimepicker({
            format: 'Y-m-d H:i',
            minDate: 0
        });
    }

    // Handle meeting type change
    if (document.getElementById('meeting_type')) {
        document.getElementById('meeting_type').addEventListener('change', function() {
            const maxParticipants = document.getElementById('max_participants');
            const requireApproval = document.getElementById('require_approval');
            
            if (this.value === 'webinar') {
                maxParticipants.value = 100;
                requireApproval.checked = true;
            } else {
                maxParticipants.value = 20;
            }
        });
    }

    // Handle participant actions
    document.querySelectorAll('.approve-participant').forEach(button => {
        button.addEventListener('click', function() {
            const meetingId = this.dataset.meetingId;
            const userId = this.dataset.userId;
            approveParticipant(meetingId, userId);
        });
    });

    document.querySelectorAll('.reject-participant').forEach(button => {
        button.addEventListener('click', function() {
            const meetingId = this.dataset.meetingId;
            const userId = this.dataset.userId;
            rejectParticipant(meetingId, userId);
        });
    });

    document.querySelectorAll('.remove-participant').forEach(button => {
        button.addEventListener('click', function() {
            const meetingId = this.dataset.meetingId;
            const userId = this.dataset.userId;
            removeParticipant(meetingId, userId);
        });
    });

    // Copy invite link
    if (document.getElementById('copyInviteLink')) {
        document.getElementById('copyInviteLink').addEventListener('click', function() {
            const inviteLink = document.getElementById('inviteLink');
            inviteLink.select();
            document.execCommand('copy');
            
            // Show tooltip or alert
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(() => {
                this.innerHTML = originalText;
            }, 2000);
        });
    }
});

function approveParticipant(meetingId, userId) {
    if (confirm('Are you sure you want to approve this participant?')) {
        fetch(`/meetings/${meetingId}/approve/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message || 'Error approving participant');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error approving participant');
        });
    }
}

function rejectParticipant(meetingId, userId) {
    if (confirm('Are you sure you want to reject this participant?')) {
        fetch(`/meetings/${meetingId}/reject/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message || 'Error rejecting participant');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error rejecting participant');
        });
    }
}

function removeParticipant(meetingId, userId) {
    if (confirm('Are you sure you want to remove this participant from the meeting?')) {
        fetch(`/meetings/${meetingId}/remove/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message || 'Error removing participant');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error removing participant');
        });
    }
}

function approveAllParticipants(meetingId) {
    if (confirm('Are you sure you want to approve all pending participants?')) {
        fetch(`/meetings/${meetingId}/approve_all`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message || 'Error approving participants');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error approving participants');
        });
    }
}

// Save meeting notes
if (document.getElementById('meetingNotesForm')) {
    document.getElementById('meetingNotesForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const notes = document.getElementById('meetingNotes').value;
        
        fetch(`/meetings/${this.dataset.meetingId}/notes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
            },
            body: JSON.stringify({ notes: notes })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('Notes saved successfully', 'success');
            } else {
                showToast('Error saving notes', 'danger');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('Error saving notes', 'danger');
        });
    });
}

// Helper function to show toast notifications
function showToast(message, type) {
    const toastContainer = document.getElementById('toastContainer') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = `toast show align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    toastContainer.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'position-fixed bottom-0 end-0 p-3';
    container.style.zIndex = '11';
    document.body.appendChild(container);
    return container;
}