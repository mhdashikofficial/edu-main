// In your main JavaScript file
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type)) {
            xhr.setRequestHeader("X-CSRFToken", $('meta[name="csrf-token"]').attr('content'));
        }
    }
});

// Initialize tooltips and event handlers
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Handle follow buttons
    document.querySelectorAll('.follow-btn').forEach(button => {
        button.addEventListener('click', function() {
            const userId = this.dataset.userId;
            const isFollowing = this.classList.contains('btn-primary');
            
            fetch(`/follow/${userId}`, {
                method: isFollowing ? 'POST' : 'POST', // Both follow/unfollow use POST in app.py
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrf_token')
                },
                body: JSON.stringify({ action: isFollowing ? 'unfollow' : 'follow' })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (isFollowing) {
                        this.classList.remove('btn-primary');
                        this.classList.add('btn-outline-primary');
                        this.textContent = 'Follow';
                    } else {
                        this.classList.remove('btn-outline-primary');
                        this.classList.add('btn-primary');
                        this.textContent = 'Following';
                    }
                    if (data.follower_count !== undefined) {
                        const followerCountEl = document.querySelector('.follower-count');
                        if (followerCountEl) {
                            followerCountEl.textContent = data.follower_count;
                        }
                    }
                }
            })
            .catch(error => {
                console.error('Error updating follow status:', error);
            });
        });
    });
    
    // Handle avatar upload
    const avatarUpload = document.getElementById('avatar-upload');
    if (avatarUpload) {
        avatarUpload.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const formData = new FormData();
                formData.append('avatar', file);
                
                fetch('/profile/avatar', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRFToken': getCookie('csrf_token')
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update all avatars on the page
                        document.querySelectorAll('.profile-avatar').forEach(el => {
                            el.src = `/static/${data.avatar}`;
                        });
                        // Update avatar in navbar if exists
                        const navbarAvatar = document.querySelector('.navbar-avatar');
                        if (navbarAvatar) {
                            navbarAvatar.src = `/static/${data.avatar}`;
                        }
                    }
                })
                .catch(error => {
                    console.error('Error uploading avatar:', error);
                });
            }
        });
    }

    // Initialize notifications and messages if user is logged in
    if (document.body.dataset.userId) {
        loadNotifications();
        loadMessagePreviews();
        setupRealTimeUpdates();
    }

    // Handle resource rating
    document.querySelectorAll('.rating-star').forEach(star => {
        star.addEventListener('click', function() {
            const resourceId = this.closest('.rating-container').dataset.resourceId;
            const rating = this.dataset.rating;
            
            fetch(`/resource/${resourceId}/rate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrf_token')
                },
                body: JSON.stringify({ rating: rating })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateRatingDisplay(resourceId, data.avg_rating, data.rating_count);
                }
            })
            .catch(error => {
                console.error('Error submitting rating:', error);
            });
        });
    });

    // Handle meeting join/leave buttons
    document.querySelectorAll('.join-meeting-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const meetingId = this.dataset.meetingId;
            joinMeeting(meetingId);
        });
    });
});

// Helper function to get cookie value
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return '';
}

// Load notifications from server
function loadNotifications() {
    fetch('/api/notifications')
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            if (data.error) {
                console.error('Error loading notifications:', data.error);
                return;
            }
            updateNotificationCount(data.unread_count || 0);
            renderNotifications(data.notifications || []);
        })
        .catch(error => {
            console.error('Error loading notifications:', error);
        });
}

// Update notification badge count
function updateNotificationCount(count) {
    const badge = document.getElementById('notificationCount');
    if (!badge) return;
    
    if (count > 0) {
        badge.textContent = count > 9 ? '9+' : count;
        badge.style.display = 'block';
    } else {
        badge.style.display = 'none';
    }
}

// Render notifications in dropdown
function renderNotifications(notifications) {
    const container = document.getElementById('notificationList');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (!notifications || notifications.length === 0) {
        container.innerHTML = '<div class="p-3 text-center text-muted">No new notifications</div>';
        return;
    }
    
    notifications.slice(0, 5).forEach(notification => {
        const element = document.createElement('a');
        element.className = `dropdown-item d-flex align-items-center ${notification.read ? '' : 'bg-light'}`;
        element.href = notification.link || '#';
        element.innerHTML = `
            <div class="me-3">
                <div class="icon-circle bg-${notification.type === 'message' ? 'primary' : 'success'}">
                    <i class="fas fa-${notification.type === 'message' ? 'envelope' : 'bell'} text-white"></i>
                </div>
            </div>
            <div>
                <div class="small text-gray-500">${formatTimeSince(notification.created_at)}</div>
                <span class="${notification.read ? '' : 'fw-bold'}">${notification.message}</span>
            </div>
        `;
        
        // Mark as read when clicked
        if (!notification.read) {
            element.addEventListener('click', () => markNotificationAsRead(notification._id));
        }
        
        container.appendChild(element);
    });
}

// Mark notification as read
function markNotificationAsRead(notificationId) {
    fetch(`/notifications/${notificationId}/read`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrf_token')
        }
    })
    .catch(error => console.error('Error marking notification as read:', error));
}

// Load message previews
function loadMessagePreviews() {
    fetch('/api/chats/conversations')
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(conversations => {
            const unreadCount = conversations.reduce((total, c) => total + (c.unread_count || 0), 0);
            updateMessageCount(unreadCount);
            renderMessagePreviews(conversations);
        })
        .catch(error => {
            console.error('Error loading message previews:', error);
            updateMessageCount(0);
            renderMessagePreviews([]);
        });
}

// Update message badge count
function updateMessageCount(count) {
    const badge = document.getElementById('messageCount');
    if (!badge) return;
    
    if (count > 0) {
        badge.textContent = count > 9 ? '9+' : count;
        badge.style.display = 'block';
    } else {
        badge.style.display = 'none';
    }
}

// Render message previews in dropdown
function renderMessagePreviews(conversations) {
    const container = document.getElementById('messageList');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (!conversations || conversations.length === 0) {
        container.innerHTML = '<div class="p-3 text-center text-muted">No messages yet</div>';
        return;
    }
    
    conversations.slice(0, 5).forEach(conversation => {
        const element = document.createElement('a');
        element.className = `dropdown-item d-flex align-items-center ${conversation.unread_count > 0 ? 'bg-light' : ''}`;
        element.href = `/chat/conversation/${conversation.chat_id}`;
        
        const lastMessageContent = conversation.last_message?.content 
            ? (conversation.last_message.content.length > 30 
                ? conversation.last_message.content.substring(0, 30) + '...' 
                : conversation.last_message.content)
            : 'No messages yet';
        
        const avatarUrl = conversation.avatar 
            ? `/static/${conversation.avatar}` 
            : conversation.role === 'educator' 
                ? '/static/images/default-avatar.png' 
                : '/static/images/default-avatar1.png';
        
        element.innerHTML = `
            <div class="dropdown-list-image me-3">
                <img class="rounded-circle" src="${avatarUrl}" alt="${conversation.name || 'User'}">
                ${conversation.unread_count > 0 
                    ? `<div class="status-indicator bg-success"></div>` 
                    : ''}
            </div>
            <div class="fw-bold">
                <div class="text-truncate">${conversation.name || 'Unknown User'}</div>
                <div class="small text-gray-500">${lastMessageContent}</div>
                <div class="small text-gray-500">${formatTimeSince(conversation.updated_at)}</div>
            </div>
        `;
        container.appendChild(element);
    });
}

// Format time since (similar to Flask's timesince filter)
function formatTimeSince(timestamp) {
    if (!timestamp) return '';
    
    let date;
    if (typeof timestamp === 'string') {
        date = new Date(timestamp);
    } else if (timestamp instanceof Date) {
        date = timestamp;
    } else {
        return '';
    }
    
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    
    // For older dates, show the actual date
    return date.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric',
        year: seconds > 31536000 ? 'numeric' : undefined
    });
}

// Set up Socket.IO for real-time updates
function setupRealTimeUpdates() {
    const socket = io();
    const currentUserId = document.body.dataset.userId;
    
    // Join user's private room for notifications
    if (currentUserId) {
        socket.emit('join_user_room', { user_id: currentUserId });
    }
    
    // Handle meeting events if on a meeting page
    const meetingId = document.getElementById('meeting-container')?.dataset.meetingId;
    if (meetingId) {
        socket.emit('join_meeting_room', { meeting_id: meetingId });
    }
    
    // Event handlers
    socket.on('new_notification', () => {
        loadNotifications(); // Refresh notifications
    });
    
    socket.on('new_message', () => {
        loadMessagePreviews(); // Refresh message previews
    });
    
    socket.on('meeting_started', (data) => {
        if (data.meeting_id === meetingId) {
            alert(`Meeting has started!`);
        }
    });
    
    socket.on('user_joined', (data) => {
        if (data.meeting_id === meetingId) {
            addMeetingParticipant(data.user_id, data.username);
        }
    });
    
    socket.on('user_left', (data) => {
        if (data.meeting_id === meetingId) {
            removeMeetingParticipant(data.user_id);
        }
    });
    
    socket.on('connect_error', (error) => {
        console.error('Socket connection error:', error);
    });
    
    socket.on('disconnect', (reason) => {
        if (reason === 'io server disconnect') {
            socket.connect();
        }
        console.log('Socket disconnected:', reason);
    });
    
    return socket;
}

// Meeting functions
function joinMeeting(meetingId) {
    console.log("JoinMeeting")
    fetch(`/meetings/${meetingId}/join`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrf_token')
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log("data",data)
        if (data.success) {
            // Initialize Jitsi meeting when joining
            initializeJitsiMeeting(meetingId);
        } else {
            alert(data.message || 'Error joining meeting');
        }
    })
    .catch(error => {
        console.error('Error joining meeting:', error);
        alert('Error joining meeting');
    });
}

function initializeJitsiMeeting(meetingId) {
    // Check if we're already on the meeting page
    const meetingContainer = document.getElementById('meeting-container');
    if (!meetingContainer) {
        // If not on meeting page, redirect to it
        window.location.href = `/meetings/${meetingId}`;
        return;
    }

    // Only initialize Jitsi if we're on the meeting page
    const jitsiDomain = "meet.jit.si";
    const roomName = `EduConnect_${meetingId}`;
    const userDisplayName = meetingContainer.dataset.userName || 'Participant';
    
    const options = {
        roomName: roomName,
        width: '100%',
        height: 500,
        parentNode: document.querySelector('#jitsi-container'),
        userInfo: {
            displayName: userDisplayName
        },
        configOverwrite: {
            startWithVideoMuted: true,
            startWithAudioMuted: true,
            disableSimulcast: false,
            enableWelcomePage: false,
            prejoinPageEnabled: false,
            requireDisplayName: true
        },
        interfaceConfigOverwrite: {
            DISABLE_JOIN_LEAVE_NOTIFICATIONS: true,
            SHOW_CHROME_EXTENSION_BANNER: false
        }
    };

    try {
        // Check if JitsiMeetExternalAPI is available
        if (typeof JitsiMeetExternalAPI !== 'undefined') {
            const api = new JitsiMeetExternalAPI(jitsiDomain, options);
            
            // Handle Jitsi events
            api.addEventListener('participantJoined', (data) => {
                console.log('Participant joined:', data);
                addMeetingParticipant(data.displayName, data.displayName);
            });
            
            api.addEventListener('participantLeft', (data) => {
                console.log('Participant left:', data);
                removeMeetingParticipant(data.displayName);
            });
            
            api.addEventListener('readyToClose', () => {
                console.log('Jitsi meeting ended');
                leaveMeeting(meetingId);
            });
            
            // Store the API instance for later use
            window.jitsiAPI = api;
        } else {
            console.error('JitsiMeetExternalAPI is not loaded');
            // Fallback to iframe if API isn't available
            loadJitsiFallback(meetingId);
        }
    } catch (error) {
        console.error('Error initializing Jitsi:', error);
        // Fallback to iframe if API fails
        loadJitsiFallback(meetingId);
    }
}

function loadJitsiFallback(meetingId) {
    const jitsiDomain = "meet.jit.si";
    const roomName = `EduConnect_${meetingId}`;
    
    const jitsiConfig = {
        'config.startWithVideoMuted': true,
        'config.startWithAudioMuted': true,
        'interfaceConfig.DISABLE_JOIN_LEAVE_NOTIFICATIONS': true,
        'config.prejoinPageEnabled': false,
        'config.disableSimulcast': false,
        'config.requireDisplayName': true,
        'config.enableWelcomePage': false
    };

    const jitsiParams = Object.entries(jitsiConfig)
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join('&');

    const jitsiUrl = `https://${jitsiDomain}/${roomName}#${jitsiParams}`;

    // Create iframe if it doesn't exist
    let iframe = document.getElementById('jitsiFrame');
    if (!iframe) {
        iframe = document.createElement('iframe');
        iframe.id = 'jitsiFrame';
        iframe.style.width = '100%';
        iframe.style.height = '500px';
        iframe.style.border = 'none';
        document.querySelector('#jitsi-container').appendChild(iframe);
    }
    
    iframe.src = jitsiUrl;
}

function leaveMeeting(meetingId) {
    fetch(`/meetings/${meetingId}/leave`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrf_token')
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.href = '/meetings';
        }
    })
    .catch(error => {
        console.error('Error leaving meeting:', error);
    });
}

// Resource rating functions
function updateRatingDisplay(resourceId, avgRating, ratingCount) {
    const ratingContainer = document.querySelector(`.rating-container[data-resource-id="${resourceId}"]`);
    if (!ratingContainer) return;
    
    // Update average rating display
    const avgRatingEl = ratingContainer.querySelector('.average-rating');
    if (avgRatingEl) {
        avgRatingEl.textContent = avgRating.toFixed(1);
    }
    
    // Update rating count
    const ratingCountEl = ratingContainer.querySelector('.rating-count');
    if (ratingCountEl) {
        ratingCountEl.textContent = `(${ratingCount})`;
    }
    
    // Highlight selected stars
    const stars = ratingContainer.querySelectorAll('.rating-star');
    stars.forEach(star => {
        star.classList.toggle('text-warning', star.dataset.rating <= avgRating);
    });
}
// Constants
// At the top of your JavaScript
const defaultEducatorAvatar = "/static/images/default-avatar.png";
const defaultStudentAvatar = "/static/images/default-avatar1.png";
const resourceId = "{{ resource._id }}";
const currentUserId = "{{ current_user.id if current_user.is_authenticated else '' }}";
const csrfToken = "{{ csrf_token() }}";
const isAdmin = {{ 'true' if is_admin() else 'false' }};
const isEducatorOwner = {{ 'true' if current_user.id == resource.educator_id else 'false' }};

// Function to handle profile picture fallback
function handleProfilePictureFallback(imgElement, role) {
    const defaultAvatar = role === 'educator' 
        ? "{{ url_for('static', filename='uploads/default-avatar.png') }}" 
        : "{{ url_for('static', filename='uploads/default-avatar1.png') }}";

    imgElement.onerror = function() {
        this.src = defaultAvatar;
        this.onerror = null;
    };

    // If the image src is empty or invalid, set the default
    if (!imgElement.src || imgElement.src.includes('undefined')) {
        imgElement.src = defaultAvatar;
    }
}

// Initialize profile pictures when page loads
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.comment img').forEach(img => {
        const role = img.closest('.comment').querySelector('.badge.bg-primary') ? 'educator' : 'student';
        handleProfilePictureFallback(img, role);
    });
});

function loadComments() {
    $.get(`/resource/${resourceId}/comments`, function (comments) {
        const commentsContainer = $('#commentsContainer');
        commentsContainer.empty();

        if (comments.length === 0) {
            commentsContainer.html(`
                <div class="alert alert-info">
                    No comments yet. Be the first to comment!
                </div>
            `);
            return;
        }

        comments.forEach(comment => {
            // Construct proper avatar URL
            let avatarUrl;
            if (comment.user.avatar) {
                if (comment.user.avatar.startsWith('http')) {
                    avatarUrl = comment.user.avatar;
                } else if (comment.user.avatar.startsWith('uploads/')) {
                    avatarUrl = `/static/${comment.user.avatar}`;
                } else {
                    avatarUrl = `/static/images/${comment.user.avatar}`;
                }
            } else {
                avatarUrl = comment.user.role === 'educator' 
                    ? '/static/images/default-avatar.png' 
                    : '/static/images/default-avatar1.png';
            }

            const canEdit = currentUserId === comment.user.id || isAdmin || isEducatorOwner;

            const commentHtml = `
                <div class="comment mb-3" id="comment-${comment.id}">
                    <div class="d-flex">
                        <img src="${avatarUrl}" 
                             class="rounded-circle me-2" width="40" height="40" 
                             alt="${comment.user.username}'s profile picture"
                             onerror="this.onerror=null; this.src='${comment.user.role === 'educator' ? '/static/images/default-avatar.png' : '/static/images/default-avatar1.png'}'" />
                        <!-- Rest of your comment HTML -->
                    </div>
                </div>
            `;

            commentsContainer.append(commentHtml);
        });
    });
}
// Comment submission
$('#commentForm').submit(function (e) {
    e.preventDefault();
    const content = $('#commentContent').val().trim();
    if (!content) return alert('Comment cannot be empty');

    $.post(`/resource/${resourceId}/comment`, {
        content: content,
        _csrf_token: csrfToken
    }, function (response) {
        if (response.success) {
            $('#commentContent').val('');
            loadComments();

            const commentCountSpan = $('span:contains("comments")');
            const currentCount = parseInt(commentCountSpan.text().match(/\d+/)[0] || '0');
            commentCountSpan.text(`(${currentCount + 1} comments)`);
        }
    }).fail(function () {
        alert('Error posting comment. Please try again.');
    });
});

// Delete comment
$(document).on('click', '.delete-comment', function () {
    const commentId = $(this).data('comment-id');
    if (!confirm('Are you sure you want to delete this comment?')) return;

    $.post(`/resource/comment/${commentId}/delete`, {
        _csrf_token: csrfToken
    }, function () {
        $(`#comment-${commentId}`).remove();

        const commentCountSpan = $('span:contains("comments")');
        const currentCount = parseInt(commentCountSpan.text().match(/\d+/)[0] || '0');
        commentCountSpan.text(`(${currentCount - 1} comments)`);
    }).fail(function () {
        alert('Error deleting comment. Please try again.');
    });
});

// Initialize
$(document).ready(function () {
    loadComments();
    document.querySelectorAll('.comment img').forEach(handleProfilePictureFallback);
});

function handleImageError(img) {
    const role = img.getAttribute('data-role') || 'student';
    img.src = role === 'educator' ? defaultEducatorAvatar : defaultStudentAvatar;
    img.onerror = null; // Prevent infinite loop
}

// Add this to your document ready handler
$(document).ready(function() {
    // Set up error handlers for all images
    document.querySelectorAll('img').forEach(img => {
        img.onerror = function() {
            handleImageError(this);
        };
    });
});

// Export functions for testing if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        getCookie,
        formatTimeSince,
        updateNotificationCount,
        updateMessageCount,
        setupRealTimeUpdates
    };
}
document.addEventListener("DOMContentLoaded", function () {
    const meetingId = "yourMeetingID"; // Replace or inject dynamically
    const jitsiDomain = "meet.jit.si";

    const jitsiConfig = {
        'config.startWithVideoMuted': true,
        'config.startWithAudioMuted': true,
        'interfaceConfig.DISABLE_JOIN_LEAVE_NOTIFICATIONS': true,
        'config.prejoinPageEnabled': false,
        'config.disableSimulcast': false,
        'config.requireDisplayName': true,
        'config.enableWelcomePage': false
    };

    const jitsiParams = Object.entries(jitsiConfig)
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join('&');

    const jitsiUrl = `https://${jitsiDomain}/${meetingId}#${jitsiParams}`;

    const iframe = document.getElementById("jitsiFrame");
    if (iframe) {
        iframe.src = jitsiUrl;
    } else {
        console.error("jitsiFrame iframe not found in the DOM");
    }
});
// In profile.html's script section or a separate JS file
$(document).ready(function() {
    // Constants
    const DEFAULT_RESOURCE_IMAGE = '/static/images/default-resource.png';
    
    // Load purchased resources when the page loads (for student profiles)
    if ($('#purchased-resources-container').length) {
        loadPurchasedResources();
    }

    // Function to load purchased resources
    function loadPurchasedResources() {
        showLoadingState();
        
        $.ajax({
            url: '/api/profile/purchased-resources',
            method: 'GET',
            headers: {
                'X-CSRFToken': $('meta[name="csrf-token"]').attr('content')
            },
            success: function(response) {
                if (response.success && response.resources && response.resources.length > 0) {
                    renderPurchasedResources(response.resources);
                } else {
                    showNoPurchasedResourcesMessage();
                }
            },
            error: function(xhr) {
                console.error('Error loading purchased resources:', xhr.responseText);
                showErrorState();
            }
        });
    }

    // Function to show loading state
    function showLoadingState() {
        const container = $('#purchased-resources-container');
        container.html(`
            <div class="col-12 text-center py-5">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2">Loading your resources...</p>
            </div>
        `);
    }

    // Function to render purchased resources
    function renderPurchasedResources(resources) {
        const container = $('#purchased-resources-container');
        container.empty();
        
        // Group resources by purchase date
        const groupedResources = resources.reduce((acc, resource) => {
            const date = resource.purchase_date || 'Unknown date';
            if (!acc[date]) {
                acc[date] = [];
            }
            acc[date].push(resource);
            return acc;
        }, {});
        
        // Sort dates in descending order
        const sortedDates = Object.keys(groupedResources).sort((a, b) => {
            return new Date(b) - new Date(a);
        });
        
        sortedDates.forEach(date => {
            // Add date header
            container.append(`
                <div class="col-12 mt-4 mb-2">
                    <h5 class="text-muted">${formatDateHeader(date)}</h5>
                    <hr>
                </div>
            `);
            
            // Add resources for this date
            groupedResources[date].forEach(resource => {
                const resourceCard = createResourceCard(resource);
                container.append(resourceCard);
            });
        });
    }

    // Helper function to create resource card HTML
    function createResourceCard(resource) {
        const thumbnailUrl = resource.thumbnail ? 
            (resource.thumbnail.startsWith('http') ? resource.thumbnail : `/static/${resource.thumbnail}`) : 
            DEFAULT_RESOURCE_IMAGE;
            
        return `
            <div class="col-md-6 col-lg-4 mb-4">
                <div class="card h-100 resource-card" data-resource-id="${resource._id}">
                    <div class="card-img-container">
                        <img src="${thumbnailUrl}" class="card-img-top" alt="${resource.title}" 
                             onerror="this.src='${DEFAULT_RESOURCE_IMAGE}'">
                        <div class="card-img-overlay d-flex justify-content-end">
                            <span class="badge ${resource.type === 'paid' ? 'bg-warning' : 'bg-success'}">
                                ${resource.type.charAt(0).toUpperCase() + resource.type.slice(1)}
                            </span>
                        </div>
                    </div>
                    <div class="card-body d-flex flex-column">
                        <h5 class="card-title">${resource.title}</h5>
                        <p class="card-text text-muted">${resource.category}</p>
                        <div class="mt-auto">
                            <div class="d-flex justify-content-between align-items-center">
                                <small class="text-muted">
                                    By ${resource.educator_name || resource.educator_username || 'Unknown'}
                                </small>
                                ${resource.type === 'paid' ? 
                                    `<span class="badge bg-info">₹${resource.price.toFixed(2)}</span>` : ''
                                }
                            </div>
                        </div>
                    </div>
                    <div class="card-footer bg-transparent d-flex justify-content-between">
                        <a href="/resource/${resource._id}" class="btn btn-sm btn-outline-primary">
                            <i class="fas fa-eye"></i> View
                        </a>
                        <a href="/download/${resource._id}" class="btn btn-sm btn-primary">
                            <i class="fas fa-download"></i> Download
                        </a>
                    </div>
                </div>
            </div>
        `;
    }

    // Helper function to format date header
    function formatDateHeader(dateString) {
        if (dateString === 'Unknown date') return dateString;
        
        const date = new Date(dateString);
        const today = new Date();
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        
        if (date.toDateString() === today.toDateString()) {
            return 'Today';
        } else if (date.toDateString() === yesterday.toDateString()) {
            return 'Yesterday';
        } else {
            return date.toLocaleDateString('en-US', { 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
            });
        }
    }

    // Function to show message when no purchased resources
    function showNoPurchasedResourcesMessage() {
        const container = $('#purchased-resources-container');
        container.html(`
            <div class="col-12 text-center py-5">
                <i class="fas fa-shopping-bag fa-3x text-muted mb-3"></i>
                <h4>No purchased resources yet</h4>
                <p class="text-muted mb-4">You haven't purchased any resources yet</p>
                <a href="/browse" class="btn btn-primary">
                    <i class="fas fa-book-open me-2"></i> Browse Resources
                </a>
            </div>
        `);
    }

    // Function to show error state
    function showErrorState() {
        const container = $('#purchased-resources-container');
        container.html(`
            <div class="col-12 text-center py-5">
                <i class="fas fa-exclamation-triangle fa-3x text-danger mb-3"></i>
                <h4>Error loading resources</h4>
                <p class="text-muted mb-4">We couldn't load your purchased resources</p>
                <button class="btn btn-outline-primary" onclick="location.reload()">
                    <i class="fas fa-sync-alt me-2"></i> Try Again
                </button>
            </div>
        `);
    }
});
document.addEventListener('DOMContentLoaded', function() {
    // Connect to Socket.IO
    const socket = io();
    
    // Handle new message notifications
    socket.on('refresh_messages', function(data) {
        // Reload the page to show new messages (simple solution)
        // In a production app, you'd want to update just the message list via AJAX
        location.reload();
    });
    
    // Initialize dropdowns
    const messageDropdown = document.getElementById('messagesDropdown');
    if (messageDropdown) {
        messageDropdown.addEventListener('shown.bs.dropdown', function() {
            // Mark messages as read when dropdown is shown
            fetch('/api/chats/mark_read', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
                },
                body: JSON.stringify({})
            });
        });
    }
});
// Socket.IO for real-time message updates
document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    
    // If user is authenticated, join their room
    {% if current_user.is_authenticated %}
        socket.emit('join_user_room', { user_id: '{{ current_user.id }}' });
    {% endif %}
    
    // Handle new message notifications
    socket.on('new_message', function(data) {
        // Update the badge count
        const badge = document.querySelector('#messagesDropdown .badge');
        const currentCount = badge ? parseInt(badge.textContent) || 0 : 0;
        const newCount = currentCount + 1;
        
        if (badge) {
            badge.textContent = newCount;
        } else {
            const newBadge = document.createElement('span');
            newBadge.className = 'position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger';
            newBadge.style.fontSize = '0.6em';
            newBadge.textContent = newCount;
            document.querySelector('#messagesDropdown').appendChild(newBadge);
        }
        
        // Show a toast notification
        toastr.info('New message from ' + data.sender_name, 'New Message', {
            timeOut: 5000,
            extendedTimeOut: 2000,
            closeButton: true,
            tapToDismiss: false,
            onclick: function() {
                window.location.href = '/chat/' + data.chat_id;
            }
        });
        
        // Pulse animation for attention
        const envelope = document.querySelector('#messagesDropdown i.fa-envelope');
        envelope.classList.add('new-message');
        setTimeout(() => {
            envelope.classList.remove('new-message');
        }, 3000);
    });
    
    // Handle page visibility changes
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden) {
            // Page became visible, refresh unread counts
            fetch('/api/chats/unread_count')
                .then(response => response.json())
                .then(data => {
                    updateUnreadBadge(data.count);
                });
        }
    });
    
    function updateUnreadBadge(count) {
        const badge = document.querySelector('#messagesDropdown .badge');
        if (count > 0) {
            if (badge) {
                badge.textContent = count;
            } else {
                const newBadge = document.createElement('span');
                newBadge.className = 'position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger';
                newBadge.style.fontSize = '0.6em';
                newBadge.textContent = count;
                document.querySelector('#messagesDropdown').appendChild(newBadge);
            }
        } else if (badge) {
            badge.remove();
        }
    }
});
// This completely disables the back button functionality
document.addEventListener('DOMContentLoaded', function() {
    // Clear any existing history
    history.pushState(null, null, document.URL);
    
    // Prevent back navigation
    window.addEventListener('popstate', function() {
        history.pushState(null, null, document.URL);
        // Optionally redirect to home
        window.location.href = '/';
    });
    
    // Clear client-side storage
    sessionStorage.clear();
    localStorage.clear();
    
    // Disable cache for this page
    window.onpageshow = function(event) {
        if (event.persisted) {
            window.location.reload();
        }
    };
});