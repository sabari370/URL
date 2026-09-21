/**
 * PhishGuard AI - QR Scanner Client JavaScript
 * Drag-and-drop file upload, instant image preview, and loading indicators.
 */

document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('qrFileInput');
    const promptArea = document.getElementById('dropzonePrompt');
    const previewContainer = document.getElementById('previewContainer');
    const imagePreview = document.getElementById('imagePreview');
    const selectedFileName = document.getElementById('selectedFileName');
    const btnReset = document.getElementById('btnResetFile');
    const form = document.getElementById('qrForm');
    const btnSubmit = document.getElementById('btnSubmitQr');
    const spinner = document.getElementById('qrSpinner');

    if (!dropzone || !fileInput) return;

    // Drag over styling
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        });
    });

    // Drop handler
    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files;
            displayPreview(files[0]);
        }
    });

    // File input change
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            displayPreview(fileInput.files[0]);
        }
    });

    function displayPreview(file) {
        if (!file.type.startsWith('image/')) {
            alert('Please upload an image file (PNG, JPG, JPEG, GIF, BMP, WEBP).');
            resetFile();
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            imagePreview.src = e.target.result;
            selectedFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            promptArea.classList.add('d-none');
            previewContainer.classList.remove('d-none');
        };
        reader.readAsDataURL(file);
    }

    function resetFile() {
        fileInput.value = '';
        imagePreview.src = '#';
        selectedFileName.textContent = '';
        previewContainer.classList.add('d-none');
        promptArea.classList.remove('d-none');
    }

    if (btnReset) {
        btnReset.addEventListener('click', (e) => {
            e.stopPropagation();
            resetFile();
        });
    }

    if (form) {
        form.addEventListener('submit', () => {
            if (btnSubmit && spinner) {
                btnSubmit.disabled = true;
                spinner.classList.remove('d-none');
            }
        });
    }
});
