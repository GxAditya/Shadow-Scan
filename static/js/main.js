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

            e.preventDefault(); // Prevent default form submission
            submitBtn.disabled = true;
            progressDiv.style.display = 'block';
            progressBar.style.width = '0%';
            progressBar.textContent = '0%';

            const formData = new FormData(form);
            const xhr = new XMLHttpRequest();

            xhr.open('POST', form.action, true);

            xhr.upload.onprogress = function(event) {
                if (event.lengthComputable) {
                    const percentComplete = Math.round((event.loaded / event.total) * 100);
                    progressBar.style.width = percentComplete + '%';
                    progressBar.textContent = percentComplete + '%';
                    progressBar.setAttribute('aria-valuenow', percentComplete);
                }
            };

            xhr.onload = function() {
                submitBtn.disabled = false;
                progressDiv.style.display = 'none'; // Hide progress bar after completion
                if (xhr.status === 200) {
                    // Assuming the server responds with a redirect to the results page
                    // or with the HTML of the results page directly.
                    // For now, let's assume it redirects or we can parse a JSON response
                    // and redirect manually.
                    // If server sends HTML of results page:
                    // document.open();
                    // document.write(xhr.responseText);
                    // document.close();
                    // If server sends JSON with a redirect URL:
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.redirect_url) {
                            window.location.href = response.redirect_url;
                        } else if (response.html_content) {
                             // If server sends HTML content directly in JSON
                            document.body.innerHTML = response.html_content; // This is a bit crude, better to target a specific div
                        } else {
                            // Fallback: if the response is the results page HTML directly
                            document.open();
                            document.write(xhr.responseText);
                            document.close();
                        }
                    } catch (error) {
                        // If response is not JSON, assume it's the results page HTML
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                    }
                } else {
                    showAlert('Error analyzing file: ' + xhr.statusText, 'danger');
                }
            };

            xhr.onerror = function() {
                submitBtn.disabled = false;
                progressDiv.style.display = 'none';
                showAlert('An error occurred during the upload.', 'danger');
            };

            xhr.send(formData);
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

    // simulateProgress function is no longer needed as we use actual progress
    // function simulateProgress() { ... }

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
