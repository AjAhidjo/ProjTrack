document.addEventListener('DOMContentLoaded', () => {
    
    // 1. Password Visibility Toggle
    const eyes = document.querySelectorAll('.toggle-eye');
    eyes.forEach(eye => {
        eye.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                this.textContent = '🙈'; 
            } else {
                passwordInput.type = 'password';
                this.textContent = ''; 
            }
        });
    });

    // 2. Auto-hide Flash Messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash-msg');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.style.transition = 'opacity 0.5s ease';
            msg.style.opacity = '0';
            setTimeout(() => msg.remove(), 500);
        }, 5000);
    });

    // 3. Client-side File Validation
    const uploadForm = document.querySelector('form[enctype="multipart/form-data"]');
    if (uploadForm) {
        uploadForm.addEventListener('submit', function(e) {
            const fileInput = this.querySelector('input[type="file"]');
            const file = fileInput.files[0];

            if (file) {
                const maxSize = 16 * 1024 * 1024; // matches server MAX_CONTENT_LENGTH
                if (file.size > maxSize) {
                    alert("⚠️ Error: File is too large! Maximum limit is 16MB.");
                    e.preventDefault();
                    return;
                }

                const allowedExtensions = /\.pdf$/i; // matches server ALLOWED_EXTENSIONS
                if (!allowedExtensions.exec(file.name)) {
                    alert("⚠️ Error: Invalid file type. Only PDF is allowed.");
                    e.preventDefault();
                    return;
                }
            }
        });
    }
});