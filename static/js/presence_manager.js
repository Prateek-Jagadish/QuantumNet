// Presence manager module
(function(){
  if (typeof io === 'undefined') return;
  try {
    const socket = window.socket || io();
    socket.on('user_status_changed', function(data){
      const el = document.querySelector(`[data-user-id="${data.user_id}"]`);
      if (!el) return;
      el.classList.toggle('online', data.status === 'online');
      el.classList.toggle('offline', data.status !== 'online');
    });
  } catch(e){}
})();
 