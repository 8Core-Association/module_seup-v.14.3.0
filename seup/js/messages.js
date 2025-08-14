function showMessage(message, type = 'success', duration = 5000) {
    const messageDiv = document.getElementById('messageDiv');
    messageDiv.classList.remove('d-none', 'alert-success', 'alert-danger');
    messageDiv.classList.add(`alert-${type}`);
    messageDiv.textContent = message;
    
    setTimeout(() => {
        messageDiv.classList.add('d-none');
        messageDiv.textContent = '';
    }, duration);
}

// TODO podesi da TIP ne mora biti success - versatilnost je