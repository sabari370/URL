/**
 * PhishGuard AI - Main Client JavaScript
 * General UI interactions, active navigation tracking, and alert helpers.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Highlight Active Nav Item
    const currentPath = window.location.pathname;
    document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
        const href = link.getAttribute('href');
        if (href && (href === currentPath || (href !== '/' && currentPath.startsWith(href)))) {
            link.classList.add('active');
        }
    });

    // 2. Auto-dismiss alerts after 6 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alertEl => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 6000);
    });

    // 3. Client-side URL sanity check
    const urlInputs = document.querySelectorAll('input[type="text"][name="url"]');
    urlInputs.forEach(input => {
        input.addEventListener('blur', function() {
            let val = this.value.trim();
            if (val && !val.startsWith('http://') && !val.startsWith('https://')) {
                // Informative hint or gentle auto-prefixing
                if (val.includes('.') && !val.includes(' ')) {
                    this.value = 'http://' + val;
                }
            }
        });
    });

    // 4. Initialize Bootstrap tooltips if any
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
});
