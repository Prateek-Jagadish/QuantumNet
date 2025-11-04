// Message status module: hooks into socket events if available
(function(){
  if (typeof io === 'undefined') return;
  try {
    const socket = window.socket || io();
    socket.on('message_delivered', function(data){
      const el = document.getElementById('status-' + data.message_id);
      if (el) { el.textContent = '✓'; el.className = 'message-status delivered'; }
    });
    socket.on('message_read', function(data){
      const el = document.getElementById('status-' + data.message_id);
      if (el) { el.textContent = '✓✓'; el.className = 'message-status read'; }
    });
  } catch(e){}
})();
 