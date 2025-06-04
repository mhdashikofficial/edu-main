document.addEventListener('DOMContentLoaded', function() {
    // Initialize meeting room functionality
    if (document.getElementById('meetingContainer')) {
        initMeetingRoom();
    }
    
    // Initialize meeting creation form
    if (document.getElementById('meetingForm')) {
        initMeetingForm();
    }
});

function initMeetingForm() {
    // Additional form validation can go here
    console.log('Meeting form initialized');
}

function initMeetingRoom() {
    const meetingId = document.getElementById('meetingContainer').dataset.meetingId;
    const isHost = document.getElementById('meetingContainer').dataset.isHost === 'true';
    
    // Connect to Socket.IO
    const socket = io.connect();
    
    // Join meeting room
    socket.emit('join_meeting_room', {
        meeting_id: meetingId,
        user_id: currentUserId,
        username: currentUsername,
        role: isHost ? 'host' : 'participant'
    });
    
    // Handle meeting controls for host
    if (isHost) {
        document.getElementById('endMeetingBtn').addEventListener('click', function() {
            if (confirm('Are you sure you want to end this meeting for all participants?')) {
                fetch(`/meeting/${meetingId}/end`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        window.location.href = `/profile/${currentUsername}`;
                    } else {
                        alert('Error ending meeting: ' + data.message);
                    }
                });
            }
        });
        
        document.getElementById('lockMeetingBtn').addEventListener('click', function() {
            const isLocked = this.dataset.locked === 'true';
            socket.emit('lock_meeting', {
                meeting_id: meetingId,
                locked: !isLocked,
                csrf_token: csrfToken
            });
        });
    }
    
    // Handle chat messages
    const chatForm = document.getElementById('chatForm');
    if (chatForm) {
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const messageInput = document.getElementById('chatMessage');
            const message = messageInput.value.trim();
            
            if (message) {
                socket.emit('meeting_message', {
                    meeting_id: meetingId,
                    message: message,
                    csrf_token: csrfToken
                });
                
                // Add message to local chat
                addChatMessage({
                    user_id: currentUserId,
                    username: currentUsername,
                    message: message,
                    timestamp: new Date().toISOString()
                });
                
                messageInput.value = '';
            }
        });
    }
    
    // Socket.IO event handlers
    socket.on('participant_joined', function(data) {
        addParticipant(data);
        addSystemMessage(`${data.username} joined the meeting`);
    });
    
    socket.on('participant_left', function(data) {
        removeParticipant(data.user_id);
        addSystemMessage(`${data.username} left the meeting`);
    });
    
    socket.on('meeting_message', function(data) {
        addChatMessage(data);
    });
    
    socket.on('meeting_ended', function(data) {
        addSystemMessage('Meeting has ended by the host');
        setTimeout(() => {
            window.location.href = '/';
        }, 3000);
    });
    
    socket.on('meeting_locked', function(data) {
        const lockBtn = document.getElementById('lockMeetingBtn');
        if (lockBtn) {
            lockBtn.textContent = data.locked ? 'Unlock Meeting' : 'Lock Meeting';
            lockBtn.dataset.locked = data.locked;
            lockBtn.classList.toggle('btn-danger', data.locked);
            lockBtn.classList.toggle('btn-secondary', !data.locked);
        }
        addSystemMessage(data.message);
    });
    
    // Helper functions
    function addParticipant(participant) {
        const participantsList = document.getElementById('participantsList');
        if (participantsList) {
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex align-items-center';
            li.dataset.userId = participant.user_id;
            
            li.innerHTML = `
                <img src="${participant.avatar || '/static/images/default-avatar.png'}" 
                     class="rounded-circle me-3" width="40" height="40">
                <div>
                    <h6 class="mb-0">${participant.username}</h6>
                    <small class="text-muted">${participant.role}</small>
                </div>
            `;
            
            participantsList.appendChild(li);
        }
    }
    
    function removeParticipant(userId) {
        const participantEl = document.querySelector(`li[data-user-id="${userId}"]`);
        if (participantEl) {
            participantEl.remove();
        }
    }
    
    function addChatMessage(message) {
        const chatMessages = document.getElementById('chatMessages');
        if (chatMessages) {
            const isCurrentUser = message.user_id === currentUserId;
            const messageClass = isCurrentUser ? 'text-end' : '';
            
            const messageEl = document.createElement('div');
            messageEl.className = `mb-2 ${messageClass}`;
            
            messageEl.innerHTML = `
                <div class="d-flex ${isCurrentUser ? 'justify-content-end' : ''}">
                    ${!isCurrentUser ? `
                        <img src="${message.avatar || '/static/images/default-avatar.png'}" 
                             class="rounded-circle me-2" width="30" height="30">
                    ` : ''}
                    <div>
                        ${!isCurrentUser ? `<small class="fw-bold">${message.username}</small><br>` : ''}
                        <div class="bg-light p-2 rounded d-inline-block">
                            ${message.message}
                        </div>
                        <small class="text-muted d-block mt-1">
                            ${new Date(message.timestamp).toLocaleTimeString()}
                        </small>
                    </div>
                </div>
            `;
            
            chatMessages.appendChild(messageEl);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    }
    
    function addSystemMessage(message) {
        const chatMessages = document.getElementById('chatMessages');
        if (chatMessages) {
            const messageEl = document.createElement('div');
            messageEl.className = 'text-center my-2';
            messageEl.innerHTML = `
                <small class="text-muted bg-light p-1 rounded">
                    <i class="fas fa-info-circle"></i> ${message}
                </small>
            `;
            chatMessages.appendChild(messageEl);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    }
    
    // Initialize Jitsi if available
    if (typeof JitsiMeetExternalAPI !== 'undefined') {
        initJitsiMeeting();
    }
    
    function initJitsiMeeting() {
        const domain = document.getElementById('meetingContainer').dataset.jitsiDomain;
        const roomName = document.getElementById('meetingContainer').dataset.jitsiRoom;
        
        const options = {
            roomName: roomName,
            width: '100%',
            height: 500,
            parentNode: document.getElementById('jitsiContainer'),
            configOverwrite: {
                startWithAudioMuted: true,
                startWithVideoMuted: false,
                enableWelcomePage: false
            },
            interfaceConfigOverwrite: {
                SHOW_JITSI_WATERMARK: false,
                SHOW_WATERMARK_FOR_GUESTS: false,
                TOOLBAR_BUTTONS: [
                    'microphone', 'camera', 'closedcaptions', 'desktop', 'fullscreen',
                    'fodeviceselection', 'hangup', 'profile', 'chat', 'settings',
                    'raisehand', 'videoquality', 'filmstrip', 'shortcuts',
                    'tileview', 'select-background', 'download', 'help'
                ]
            },
            userInfo: {
                displayName: currentUsername,
                email: currentUserEmail || ''
            }
        };
        
        const api = new JitsiMeetExternalAPI(domain, options);
        
        api.executeCommand('subject', document.title);
        
        api.on('participantJoined', function(data) {
            console.log('Participant joined:', data);
        });
        
        api.on('participantLeft', function(data) {
            console.log('Participant left:', data);
        });
        
        api.on('readyToClose', function() {
            window.location.href = '/';
        });
    }
}