document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('upload-form');
    const fileInput = document.getElementById('file-input');
    const submitBtn = document.getElementById('submit-btn');
    const progressBar = document.getElementById('progress-bar');
    const progressDiv = document.getElementById('progress-div');

    if (form) {
        form.onsubmit = function(e) {
            if (!fileInput.files.length) {
                e.preventDefault();
                showAlert('Please select a file first', 'danger');
                return false;
            }

            const file = fileInput.files[0];
            if (file.size > 10 * 1024 * 1024) {  // 10MB
                e.preventDefault();
                showAlert('File size must be less than 10MB', 'danger');
                return false;
            }

            submitBtn.disabled = true;
            progressDiv.style.display = 'block';
            progressBar.style.width = '0%';
            simulateProgress();
        };
    }

    if (fileInput) {
        fileInput.onchange = function() {
            const fileName = this.files[0]?.name;
            if (fileName) {
                document.getElementById('file-name').textContent = fileName;
            }
        };
    }

    function simulateProgress() {
        let progress = 0;
        const interval = setInterval(() => {
            progress += 5;
            if (progress <= 90) {
                progressBar.style.width = progress + '%';
                progressBar.setAttribute('aria-valuenow', progress);
                progressBar.textContent = progress + '%';
            }
        }, 100);

        setTimeout(() => clearInterval(interval), 2000);
    }

    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        document.querySelector('.alerts').appendChild(alertDiv);
        
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
});
