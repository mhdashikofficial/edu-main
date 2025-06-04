document.addEventListener('DOMContentLoaded', function() {
    // Initialize Socket.IO connection
    const socket = io();
    
    // Get current chat ID from URL
    const pathParts = window.location.pathname.split('/');
    const chatId = pathParts[pathParts.length - 1];
    
    // Join the chat room
    socket.emit('join_chat', {
        chat_id: chatId,
        user_id: currentUserId // This should be set in your template
    });
    
    // Handle sending messages
    const chatForm = document.getElementById('chat-form');
    if (chatForm) {
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();
            
            if (message) {
                // Send message via Socket.IO
                socket.emit('send_message', {
                    chat_id: chatId,
                    recipient_id: document.getElementById('recipient-id').value,
                    message: message
                });
                
                // Add message to UI immediately
                addMessageToUI({
                    sender_id: currentUserId,
                    message: message,
                    timestamp: new Date(),
                    read: false
                });
                
                // Clear input
                messageInput.value = '';
            }
        });
    }
    
    // Listen for new messages
    socket.on('new_message', function(data) {
        if (data.chat_id === chatId) {
            addMessageToUI(data);
            
            // Mark as read if it's our chat
            if (data.sender_id !== currentUserId) {
                socket.emit('mark_as_read', {
                    chat_id: chatId,
                    message_id: data.message_id
                });
            }
        }
    });
    
    // Function to add message to UI
    function addMessageToUI(message) {
        const messagesContainer = document.getElementById('chat-messages');
        const isSent = message.sender_id === currentUserId;
        
        const messageElement = document.createElement('div');
        messageElement.className = `message ${isSent ? 'sent' : 'received'}`;
        
        const timestamp = new Date(message.timestamp);
        const timeString = timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        messageElement.innerHTML = `
            <div class="message-content">
                <div class="message-text">${message.message}</div>
                <div class="message-time">
                    ${timeString}
                    ${isSent ? `<i class="fas fa-check${message.read ? '-double' : ''} ms-1 ${message.read ? 'text-primary' : 'text-muted'}"></i>` : ''}
                </div>
            </div>
        `;
        
        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
    
    // Load more messages when scrolling to top
    const messagesContainer = document.getElementById('chat-messages');
    if (messagesContainer) {
        messagesContainer.addEventListener('scroll', function() {
            if (this.scrollTop === 0) {
                loadMoreMessages();
            }
        });
    }
    
    // Function to load more messages
    function loadMoreMessages() {
        const oldestMessage = document.querySelector('.message');
        if (!oldestMessage) return;
        
        const oldestMessageId = oldestMessage.dataset.messageId;
        fetch(`/api/chat/messages?chat_id=${chatId}&before=${oldestMessageId}`)
        .then(response => response.json())
        .then(data => {
            if (data.messages && data.messages.length > 0) {
                // Add messages to the top
                data.messages.reverse().forEach(message => {
                    addMessageToUI(message, true);
                });
                
                // Adjust scroll position to stay at the same message
                const newMessages = document.querySelectorAll('.message');
                if (newMessages.length > 0) {
                    messagesContainer.scrollTop = newMessages[0].offsetHeight * data.messages.length;
                }
            }
        });
    }
});