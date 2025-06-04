// WebRTC Configuration
const configuration = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' }
    ]
};

// Global variables
let localStream;
let peerConnections = {};
let socket;
let screenStream;
let isVideoOn = true;
let isAudioOn = true;

// Initialize meeting
function initializeMeeting(meetingId, userId, isEducator, meetingType) {
    // Connect to Socket.IO
    socket = io();
    
    // Join meeting room
    socket.emit('join_meeting', { meeting_id: meetingId });
    
    // Setup media based on meeting type
    setupMedia(meetingType).then(() => {
        // Listen for new participants
        socket.on('user_joined', handleNewParticipant);
        
        // Listen for participants leaving
        socket.on('user_left', handleParticipantLeft);
        
        // Listen for WebRTC signaling
        socket.on('webrtc_offer', handleOffer);
        socket.on('webrtc_answer', handleAnswer);
        socket.on('ice_candidate', handleICECandidate);
        
        // Listen for meeting controls
        setupMeetingControls(meetingType);
    }).catch(error => {
        console.error('Error setting up media:', error);
    });
}

// Setup media (video/audio/screen)
async function setupMedia(meetingType) {
    try {
        const constraints = {
            video: meetingType !== 'audio',
            audio: true
        };
        
        localStream = await navigator.mediaDevices.getUserMedia(constraints);
        
        // Display local video
        const localVideo = document.getElementById('localVideo');
        localVideo.srcObject = localStream;
        
        // Hide placeholder if video is enabled
        if (meetingType !== 'audio') {
            document.getElementById('noVideoPlaceholder').style.display = 'none';
        }
        
        return true;
    } catch (error) {
        console.error('Error accessing media devices:', error);
        throw error;
    }
}

// Handle new participant joining
function handleNewParticipant(data) {
    const userId = data.user_id;
    
    // Don't create connection to self
    if (userId === currentUserId) return;
    
    // Create peer connection
    const peerConnection = new RTCPeerConnection(configuration);
    peerConnections[userId] = peerConnection;
    
    // Add local stream to connection
    localStream.getTracks().forEach(track => {
        peerConnection.addTrack(track, localStream);
    });
    
    // ICE candidate handler
    peerConnection.onicecandidate = event => {
        if (event.candidate) {
            socket.emit('ice_candidate', {
                meeting_id: meetingId,
                candidate: event.candidate,
                target_user_id: userId
            });
        }
    };
    
    // Track handler (remote streams)
    peerConnection.ontrack = event => {
        const remoteVideo = document.createElement('video');
        remoteVideo.autoplay = true;
        remoteVideo.className = 'rounded shadow-sm';
        remoteVideo.style.width = '100%';
        remoteVideo.srcObject = event.streams[0];
        
        const videoContainer = document.createElement('div');
        videoContainer.className = 'position-relative';
        videoContainer.style.width = 'calc(50% - 0.5rem)';
        videoContainer.dataset.userId = userId;
        
        const usernameLabel = document.createElement('div');
        usernameLabel.className = 'text-center small mt-1';
        usernameLabel.textContent = data.username;
        
        videoContainer.appendChild(remoteVideo);
        videoContainer.appendChild(usernameLabel);
        
        document.getElementById('remoteVideosContainer').appendChild(videoContainer);
        document.getElementById('noVideoPlaceholder').style.display = 'none';
    };
    
    // Create offer
    peerConnection.createOffer()
        .then(offer => peerConnection.setLocalDescription(offer))
        .then(() => {
            socket.emit('webrtc_offer', {
                meeting_id: meetingId,
                offer: peerConnection.localDescription,
                target_user_id: userId
            });
        })
        .catch(error => console.error('Error creating offer:', error));
}

// Handle participant leaving
function handleParticipantLeft(data) {
    const userId = data.user_id;
    
    // Close peer connection
    if (peerConnections[userId]) {
        peerConnections[userId].close();
        delete peerConnections[userId];
    }
    
    // Remove video element
    const videoElement = document.querySelector(`[data-user-id="${userId}"]`);
    if (videoElement) {
        videoElement.remove();
    }
    
    // Show placeholder if no videos left
    if (document.getElementById('remoteVideosContainer').children.length === 0) {
        document.getElementById('noVideoPlaceholder').style.display = 'flex';
    }
}

// Handle WebRTC offer
function handleOffer(data) {
    const userId = data.from_user_id;
    const offer = data.offer;
    
    const peerConnection = new RTCPeerConnection(configuration);
    peerConnections[userId] = peerConnection;
    
    // Add local stream
    localStream.getTracks().forEach(track => {
        peerConnection.addTrack(track, localStream);
    });
    
    // ICE candidate handler
    peerConnection.onicecandidate = event => {
        if (event.candidate) {
            socket.emit('ice_candidate', {
                meeting_id: meetingId,
                candidate: event.candidate,
                target_user_id: userId
            });
        }
    };
    
    // Track handler
    peerConnection.ontrack = event => {
        const remoteVideo = document.createElement('video');
        remoteVideo.autoplay = true;
        remoteVideo.className = 'rounded shadow-sm';
        remoteVideo.style.width = '100%';
        remoteVideo.srcObject = event.streams[0];
        
        const videoContainer = document.createElement('div');
        videoContainer.className = 'position-relative';
        videoContainer.style.width = 'calc(50% - 0.5rem)';
        videoContainer.dataset.userId = userId;
        
        const usernameLabel = document.createElement('div');
        usernameLabel.className = 'text-center small mt-1';
        usernameLabel.textContent = 'Participant'; // Would need username lookup
        
        videoContainer.appendChild(remoteVideo);
        videoContainer.appendChild(usernameLabel);
        
        document.getElementById('remoteVideosContainer').appendChild(videoContainer);
        document.getElementById('noVideoPlaceholder').style.display = 'none';
    };
    
    // Set remote description and create answer
    peerConnection.setRemoteDescription(offer)
        .then(() => peerConnection.createAnswer())
        .then(answer => peerConnection.setLocalDescription(answer))
        .then(() => {
            socket.emit('webrtc_answer', {
                meeting_id: meetingId,
                answer: peerConnection.localDescription,
                target_user_id: userId
            });
        })
        .catch(error => console.error('Error handling offer:', error));
}

// Handle WebRTC answer
function handleAnswer(data) {
    const userId = data.from_user_id;
    const answer = data.answer;
    
    if (peerConnections[userId]) {
        peerConnections[userId].setRemoteDescription(answer)
            .catch(error => console.error('Error setting answer:', error));
    }
}

// Handle ICE candidate
function handleICECandidate(data) {
    const userId = data.from_user_id;
    const candidate = data.candidate;
    
    if (peerConnections[userId]) {
        peerConnections[userId].addIceCandidate(new RTCIceCandidate(candidate))
            .catch(error => console.error('Error adding ICE candidate:', error));
    }
}

// Setup meeting controls
function setupMeetingControls(meetingType) {
    const toggleVideoBtn = document.getElementById('toggleVideoBtn');
    const toggleAudioBtn = document.getElementById('toggleAudioBtn');
    const screenShareBtn = document.getElementById('screenShareBtn');
    
    // Toggle video
    if (toggleVideoBtn) {
        toggleVideoBtn.addEventListener('click', function() {
            const videoTrack = localStream.getVideoTracks()[0];
            if (videoTrack) {
                isVideoOn = !videoTrack.enabled;
                videoTrack.enabled = isVideoOn;
                this.innerHTML = `<i class="fas fa-video"></i> ${isVideoOn ? 'Video On' : 'Video Off'}`;
                this.classList.toggle('btn-outline-primary');
                this.classList.toggle('btn-outline-secondary');
            }
        });
    }
    
    // Toggle audio
    if (toggleAudioBtn) {
        toggleAudioBtn.addEventListener('click', function() {
            const audioTrack = localStream.getAudioTracks()[0];
            if (audioTrack) {
                isAudioOn = !audioTrack.enabled;
                audioTrack.enabled = isAudioOn;
                this.innerHTML = `<i class="fas fa-microphone"></i> ${isAudioOn ? 'Mic On' : 'Mic Off'}`;
                this.classList.toggle('btn-outline-primary');
                this.classList.toggle('btn-outline-secondary');
            }
        });
    }
    
    // Screen sharing
    if (screenShareBtn && meetingType === 'screen') {
        screenShareBtn.addEventListener('click', async function() {
            try {
                if (!screenStream) {
                    screenStream = await navigator.mediaDevices.getDisplayMedia({
                        video: true,
                        audio: false
                    });
                    
                    // Replace video track in all peer connections
                    const screenTrack = screenStream.getVideoTracks()[0];
                    Object.values(peerConnections).forEach(pc => {
                        const sender = pc.getSenders().find(s => s.track.kind === 'video');
                        if (sender) sender.replaceTrack(screenTrack);
                    });
                    
                    this.innerHTML = '<i class="fas fa-stop"></i> Stop Sharing';
                    this.classList.add('btn-danger');
                    this.classList.remove('btn-outline-secondary');
                    
                    // Handle when user stops sharing
                    screenTrack.onended = () => {
                        stopScreenSharing();
                    };
                } else {
                    stopScreenSharing();
                }
            } catch (error) {
                console.error('Error sharing screen:', error);
            }
        });
    }
}

// Stop screen sharing
function stopScreenSharing() {
    if (screenStream) {
        const screenShareBtn = document.getElementById('screenShareBtn');
        const localVideo = document.getElementById('localVideo');
        
        // Get original video track
        const videoTrack = localStream.getVideoTracks()[0];
        
        // Replace track in all peer connections
        Object.values(peerConnections).forEach(pc => {
            const sender = pc.getSenders().find(s => s.track.kind === 'video');
            if (sender && videoTrack) sender.replaceTrack(videoTrack);
        });
        
        // Update UI
        if (screenShareBtn) {
            screenShareBtn.innerHTML = '<i class="fas fa-desktop"></i> Share Screen';
            screenShareBtn.classList.remove('btn-danger');
            screenShareBtn.classList.add('btn-outline-secondary');
        }
        
        // Stop screen stream
        screenStream.getTracks().forEach(track => track.stop());
        screenStream = null;
    }
}

// Clean up when leaving
window.addEventListener('beforeunload', function() {
    if (socket) {
        socket.emit('leave_meeting', { meeting_id: meetingId });
    }
    
    // Close all peer connections
    Object.values(peerConnections).forEach(pc => pc.close());
    
    // Stop all media tracks
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
    }
    
    if (screenStream) {
        screenStream.getTracks().forEach(track => track.stop());
    }
});

// WebRTC configuration and functions
const configuration = {
    iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
  };
  
  let localStream;
  let peerConnections = {};
  let socket;
  
  function initializeMeeting(meetingId) {
    socket = io();
    
    // Get user media
    navigator.mediaDevices.getUserMedia({ video: true, audio: true })
      .then(stream => {
        localStream = stream;
        document.getElementById('localVideo').srcObject = stream;
        
        // Join meeting room
        socket.emit('join_meeting_room', { meeting_id: meetingId });
        
        // Set up socket listeners
        setupSocketListeners(meetingId);
      })
      .catch(handleError);
  }
  
  function setupSocketListeners(meetingId) {
    socket.on('user_joined', handleUserJoined);
    socket.on('user_left', handleUserLeft);
    socket.on('offer', handleOffer);
    socket.on('answer', handleAnswer);
    socket.on('ice-candidate', handleNewICECandidate);
    
    // Join the Socket.IO room for this meeting
    socket.emit('join_meeting_room', { meeting_id: meetingId });
  }
  
  // Implement WebRTC functions (createOffer, createAnswer, etc.)
  // ... more WebRTC implementation code ...
  // webrtc.js - Handles all WebRTC functionality
class WebRTCManager {
    constructor(meetingData, socket) {
      this.meetingData = meetingData;
      this.socket = socket;
      this.peerConnections = {};
      this.localStream = null;
      this.screenStream = null;
      this.mediaConstraints = meetingData.mediaConstraints;
      
      // Initialize WebRTC
      this.initialize();
    }
  
    async initialize() {
      try {
        // Get local media stream
        this.localStream = await navigator.mediaDevices.getUserMedia(this.mediaConstraints);
        document.getElementById('hostVideo').srcObject = this.localStream;
        
        // Notify server we're ready
        this.socket.emit('meeting_ready', { meeting_id: this.meetingData.id });
        
        // Set up socket listeners
        this.setupSocketListeners();
      } catch (error) {
        console.error('Error getting media devices:', error);
        alert('Could not access your camera/microphone. Please check permissions.');
      }
    }
  
    setupSocketListeners() {
      // When a new participant joins
      this.socket.on('user_joined', (data) => {
        this.createPeerConnection(data.user_id);
      });
  
      // When a participant leaves
      this.socket.on('user_left', (data) => {
        this.removeParticipant(data.user_id);
      });
  
      // WebRTC signaling
      this.socket.on('webrtc_offer', (data) => {
        this.handleOffer(data.from_user_id, data.offer);
      });
  
      this.socket.on('webrtc_answer', (data) => {
        this.handleAnswer(data.from_user_id, data.answer);
      });
  
      this.socket.on('ice_candidate', (data) => {
        this.handleIceCandidate(data.from_user_id, data.candidate);
      });
  
      // Screen sharing events
      this.socket.on('screen_share_started', (data) => {
        this.showScreenShare(data.user_id, data.username);
      });
  
      this.socket.on('screen_share_ended', (data) => {
        this.hideScreenShare();
      });
    }
  
    async createPeerConnection(userId) {
      if (this.peerConnections[userId]) return;
  
      const configuration = {
        iceServers: this.meetingData.iceServers
      };
  
      const peerConnection = new RTCPeerConnection(configuration);
      this.peerConnections[userId] = peerConnection;
  
      // Add local stream to connection
      if (this.localStream) {
        this.localStream.getTracks().forEach(track => {
          peerConnection.addTrack(track, this.localStream);
        });
      }
  
      // Handle ICE candidates
      peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
          this.socket.emit('ice_candidate', {
            meeting_id: this.meetingData.id,
            target_user_id: userId,
            candidate: event.candidate
          });
        }
      };
  
      // Handle remote stream
      peerConnection.ontrack = (event) => {
        const videoContainer = this.createVideoElement(userId);
        const videoElement = videoContainer.querySelector('video');
        videoElement.srcObject = event.streams[0];
      };
  
      // Create offer if we're the host
      if (this.meetingData.isHost) {
        try {
          const offer = await peerConnection.createOffer();
          await peerConnection.setLocalDescription(offer);
          
          this.socket.emit('webrtc_offer', {
            meeting_id: this.meetingData.id,
            target_user_id: userId,
            offer: offer
          });
        } catch (error) {
          console.error('Error creating offer:', error);
        }
      }
    }
  
    async handleOffer(fromUserId, offer) {
      if (!this.peerConnections[fromUserId]) {
        await this.createPeerConnection(fromUserId);
      }
  
      const peerConnection = this.peerConnections[fromUserId];
      
      try {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);
        
        this.socket.emit('webrtc_answer', {
          meeting_id: this.meetingData.id,
          target_user_id: fromUserId,
          answer: answer
        });
      } catch (error) {
        console.error('Error handling offer:', error);
      }
    }
  
    async handleAnswer(fromUserId, answer) {
      const peerConnection = this.peerConnections[fromUserId];
      if (peerConnection) {
        try {
          await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
        } catch (error) {
          console.error('Error handling answer:', error);
        }
      }
    }
  
    async handleIceCandidate(fromUserId, candidate) {
      const peerConnection = this.peerConnections[fromUserId];
      if (peerConnection) {
        try {
          await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
        } catch (error) {
          console.error('Error adding ICE candidate:', error);
        }
      }
    }
  
    createVideoElement(userId) {
      const videoGrid = document.getElementById('videoGrid');
      const videoContainer = document.createElement('div');
      videoContainer.className = 'video-container';
      videoContainer.id = `videoContainer_${userId}`;
      
      const videoElement = document.createElement('video');
      videoElement.id = `video_${userId}`;
      videoElement.autoplay = true;
      videoElement.playsInline = true;
      
      const videoInfo = document.createElement('div');
      videoInfo.className = 'video-info';
      videoInfo.innerHTML = `
        <span class="username">${userId === this.meetingData.userId ? 'You' : 'Participant'}</span>
        <span class="user-role">${userId === this.meetingData.educatorId ? 'Host' : ''}</span>
      `;
      
      videoContainer.appendChild(videoElement);
      videoContainer.appendChild(videoInfo);
      videoGrid.appendChild(videoContainer);
      
      return videoContainer;
    }
  
    removeParticipant(userId) {
      // Close peer connection
      if (this.peerConnections[userId]) {
        this.peerConnections[userId].close();
        delete this.peerConnections[userId];
      }
      
      // Remove video element
      const videoContainer = document.getElementById(`videoContainer_${userId}`);
      if (videoContainer) {
        videoContainer.remove();
      }
    }
  
    async toggleScreenShare() {
      if (this.screenStream) {
        await this.stopScreenShare();
      } else {
        await this.startScreenShare();
      }
    }
  
    async startScreenShare() {
      try {
        this.screenStream = await navigator.mediaDevices.getDisplayMedia({
          video: this.meetingData.screenSharingConstraints.video,
          audio: false
        });
  
        // Notify server
        this.socket.emit('start_screen_share', {
          meeting_id: this.meetingData.id
        });
  
        // Add screen share tracks to all peer connections
        Object.keys(this.peerConnections).forEach(userId => {
          const sender = this.peerConnections[userId].getSenders().find(s => s.track && s.track.kind === 'video');
          if (sender) {
            sender.replaceTrack(this.screenStream.getVideoTracks()[0]);
          } else {
            this.peerConnections[userId].addTrack(this.screenStream.getVideoTracks()[0], this.screenStream);
          }
        });
  
        // Show local screen share preview
        this.showScreenShare(this.meetingData.userId, 'You');
  
        // Handle when user stops screen sharing via browser UI
        this.screenStream.getVideoTracks()[0].onended = () => {
          this.stopScreenShare();
        };
  
      } catch (error) {
        console.error('Error starting screen share:', error);
      }
    }
  
    async stopScreenShare() {
      if (!this.screenStream) return;
  
      // Notify server
      this.socket.emit('stop_screen_share', {
        meeting_id: this.meetingData.id
      });
  
      // Stop all screen share tracks
      this.screenStream.getTracks().forEach(track => track.stop());
      this.screenStream = null;
      this.hideScreenShare();
  
      // Switch back to camera video for all peer connections
      if (this.localStream) {
        Object.keys(this.peerConnections).forEach(userId => {
          const sender = this.peerConnections[userId].getSenders().find(s => s.track && s.track.kind === 'video');
          if (sender && this.localStream) {
            sender.replaceTrack(this.localStream.getVideoTracks()[0]);
          }
        });
      }
    }
  
    showScreenShare(userId, username) {
      const screenShareContainer = document.getElementById('screenShareContainer');
      const screenShareVideo = document.getElementById('screenShareVideo');
      const screenSharerName = document.getElementById('screenSharerName');
      
      screenSharerName.textContent = username;
      screenShareContainer.style.display = 'block';
      
      if (userId === this.meetingData.userId) {
        // Local screen share
        screenShareVideo.srcObject = this.screenStream;
      }
    }
  
    hideScreenShare() {
      const screenShareContainer = document.getElementById('screenShareContainer');
      const screenShareVideo = document.getElementById('screenShareVideo');
      
      screenShareVideo.srcObject = null;
      screenShareContainer.style.display = 'none';
    }
  
    async toggleAudio() {
      if (this.localStream) {
        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
          audioTrack.enabled = !audioTrack.enabled;
          document.getElementById('toggleAudio').classList.toggle('muted', !audioTrack.enabled);
        }
      }
    }
  
    async toggleVideo() {
      if (this.localStream) {
        const videoTrack = this.localStream.getVideoTracks()[0];
        if (videoTrack) {
          videoTrack.enabled = !videoTrack.enabled;
          document.getElementById('toggleVideo').classList.toggle('disabled', !videoTrack.enabled);
        }
      }
    }
  
    cleanup() {
      // Close all peer connections
      Object.keys(this.peerConnections).forEach(userId => {
        this.peerConnections[userId].close();
      });
      this.peerConnections = {};
  
      // Stop local media streams
      if (this.localStream) {
        this.localStream.getTracks().forEach(track => track.stop());
      }
      
      if (this.screenStream) {
        this.screenStream.getTracks().forEach(track => track.stop());
      }
    }
  }
  
  // Initialize when DOM is loaded
  document.addEventListener('DOMContentLoaded', () => {
    window.webrtcManager = new WebRTCManager(meetingData, socket);
    
    // Setup UI controls
    document.getElementById('toggleAudio').addEventListener('click', () => webrtcManager.toggleAudio());
    document.getElementById('toggleVideo').addEventListener('click', () => webrtcManager.toggleVideo());
    
    if (document.getElementById('toggleScreenShare')) {
      document.getElementById('toggleScreenShare').addEventListener('click', () => webrtcManager.toggleScreenShare());
    }
  });