document.addEventListener('DOMContentLoaded', function() {
    // Connect to Socket.IO
    const socket = io();
    
    // Handle meeting approval notifications
    socket.on('meeting_approved_notification', function(data) {
        const meetingId = data.meeting_id;
        const educatorName = data.educator_username;
        
        // Show notification to user
        showNotification(
            'Meeting Approved', 
            `Your request to join the meeting has been approved by ${educatorName}`,
            'success'
        );
        
        // Update UI if on the meeting page
        if (window.location.pathname.includes(meetingId)) {
            window.location.reload(); // Refresh to show updated status
        }
    });
    
    // Handle meeting rejection notifications
    socket.on('meeting_declined_notification', function(data) {
        const meetingId = data.meeting_id;
        
        // Show notification to user
        showNotification(
            'Meeting Request Declined', 
            'Your request to join the meeting was declined by the educator',
            'error'
        );
        
        // Update UI if on the meeting page
        if (window.location.pathname.includes(meetingId)) {
            window.location.reload(); // Refresh to show updated status
        }
    });
    
    // Helper function to show notifications
    function showNotification(title, message, type) {
        // You can use Toastr, SweetAlert, or any other notification library
        if (typeof Toastr !== 'undefined') {
            toastr[type](message, title);
        } else if (typeof Swal !== 'undefined') {
            Swal.fire(title, message, type);
        } else {
            alert(`${title}: ${message}`);
        }
    }
});