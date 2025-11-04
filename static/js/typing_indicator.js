// Typing indicator module
(function(){
  if (typeof io === 'undefined') return;
  try {
    const socket = window.socket || io();
    socket.on('user_typing', function(data){
      const chat = document.getElementById('chat-messages');
      if (!chat) return;
      let ind = document.getElementById('ti-ind');
      if (!ind){ ind = document.createElement('div'); ind.id='ti-ind'; ind.className='typing-indicator'; chat.appendChild(ind); }
      ind.textContent = (data.username||'Someone') + ' is typing...';
      ind.style.display = 'block';
      setTimeout(()=>{ if (ind) ind.style.display='none'; }, 3000);
    });
    socket.on('user_stopped_typing', function(){
      const ind = document.getElementById('ti-ind'); if (ind) ind.style.display='none';
    });
  } catch(e){}
})();
 