self.addEventListener('push', function(event) {
    const data = event.data ? event.data.text() : 'No payload';

    const options = {
        body: data,
        icon: '/icon.png', // Optional icon
        vibrate: [100, 50, 100],
        actions: [
            { action: 'explore', title: 'Explore this', icon: '/check.png' },
            { action: 'close', title: 'Close', icon: '/close.png' }
        ]
    };

    event.waitUntil(
        self.registration.showNotification('Push Notification', options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();

    if (event.action === 'explore') {
        clients.openWindow('https://example.com'); // Change URL
    } else {
        console.log('Notification closed');
    }
});
