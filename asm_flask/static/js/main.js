// Main JavaScript for ASM Tool
document.addEventListener('DOMContentLoaded', function() {
    // Flash message auto-dismiss
    const flashMessages = document.querySelectorAll('.flash');
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            message.style.transform = 'translateX(100%)';
            setTimeout(() => {
                message.remove();
            }, 300);
        }, 5000);
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            if(this.getAttribute('href') !== '#') {
                e.preventDefault();
                
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Form validation
    const domainForm = document.getElementById('domain-form');
    if (domainForm) {
        domainForm.addEventListener('submit', function(e) {
            const domainInput = document.getElementById('domain');
            if (domainInput && domainInput.value.trim() === '') {
                e.preventDefault();
                domainInput.classList.add('error');
                const errorMsg = document.createElement('small');
                errorMsg.classList.add('error');
                errorMsg.textContent = 'Domain is required';
                domainInput.parentNode.appendChild(errorMsg);
            }
        });
    }

    // CSV file validation
    const csvForm = document.getElementById('csv-form');
    if (csvForm) {
        csvForm.addEventListener('submit', function(e) {
            const fileInput = document.querySelector('input[type="file"]');
            if (fileInput && (!fileInput.files || fileInput.files.length === 0)) {
                e.preventDefault();
                fileInput.classList.add('error');
                const errorMsg = document.createElement('small');
                errorMsg.classList.add('error');
                errorMsg.textContent = 'Please select a CSV file';
                fileInput.parentNode.appendChild(errorMsg);
            }
        });
    }

    // Status page auto-refresh
    const scanStatus = document.getElementById('scan-status');
    if (scanStatus && (scanStatus.classList.contains('in_progress') || scanStatus.classList.contains('queued'))) {
        const progressBar = document.getElementById('progress-bar');
        const progressText = document.getElementById('progress-text');
        const currentModule = document.getElementById('current-module');
        const scanId = document.getElementById('scan-id').textContent;
        
        // Poll for updates every 3 seconds
        const statusInterval = setInterval(function() {
            fetch('/api/status/' + scanId)
                .then(response => response.json())
                .then(data => {
                    // Update progress
                    if (progressBar) {
                        progressBar.style.width = data.progress + '%';
                    }
                    if (progressText) {
                        progressText.textContent = data.progress + '% complete';
                    }
                    
                    // Update current module if available
                    if (currentModule && data.current_module) {
                        currentModule.textContent = 'Current task: ' + data.current_module.replace(/_/g, ' ');
                    }
                    
                    // Update status
                    if (data.status !== scanStatus.classList[1]) {
                        scanStatus.classList.remove(scanStatus.classList[1]);
                        scanStatus.classList.add(data.status);
                        
                        if (data.status === 'completed') {
                            scanStatus.textContent = 'Completed';
                            clearInterval(statusInterval);
                            // Reload the page to show results
                            window.location.reload();
                        } else if (data.status === 'failed') {
                            scanStatus.textContent = 'Failed';
                            clearInterval(statusInterval);
                            // Show error message
                            if (data.error) {
                                currentModule.textContent = 'Error: ' + data.error;
                                currentModule.style.color = 'var(--error-color)';
                            }
                        }
                    }
                })
                .catch(error => {
                    console.error('Error fetching status:', error);
                });
        }, 3000);
    }

    // Dashboard delete scan functionality
    const deleteButtons = document.querySelectorAll('.delete-scan');
    const deleteModal = document.getElementById('delete-modal');
    if (deleteButtons.length > 0 && deleteModal) {
        const confirmDelete = document.getElementById('confirm-delete');
        const cancelDelete = document.getElementById('cancel-delete');
        const closeModal = document.querySelector('.close');
        
        let scanIdToDelete = null;
        
        deleteButtons.forEach(button => {
            button.addEventListener('click', function() {
                scanIdToDelete = this.dataset.scanId;
                deleteModal.classList.add('active');
            });
        });
        
        if (closeModal) {
            closeModal.addEventListener('click', function() {
                deleteModal.classList.remove('active');
            });
        }
        
        if (cancelDelete) {
            cancelDelete.addEventListener('click', function() {
                deleteModal.classList.remove('active');
            });
        }
        
        if (confirmDelete) {
            confirmDelete.addEventListener('click', function() {
                if (scanIdToDelete) {
                    fetch('/api/delete-scan/' + scanIdToDelete, {
                        method: 'DELETE'
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Reload the page to reflect the deletion
                            window.location.reload();
                        } else {
                            alert('Failed to delete scan: ' + (data.error || 'Unknown error'));
                        }
                    })
                    .catch(error => {
                        alert('Error: ' + error.message);
                    })
                    .finally(() => {
                        deleteModal.classList.remove('active');
                    });
                }
            });
        }
        
        // Close modal when clicking outside
        window.addEventListener('click', function(event) {
            if (event.target === deleteModal) {
                deleteModal.classList.remove('active');
            }
        });
    }

    // Documentation sidebar navigation
    const docLinks = document.querySelectorAll('.documentation-sidebar a');
    if (docLinks.length > 0) {
        docLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Remove active class from all links
                docLinks.forEach(l => l.classList.remove('active'));
                
                // Add active class to clicked link
                this.classList.add('active');
                
                // Get the target section
                const targetId = this.getAttribute('href').substring(1);
                const targetSection = document.getElementById(targetId);
                
                if (targetSection) {
                    // Scroll to the target section
                    window.scrollTo({
                        top: targetSection.offsetTop - 100,
                        behavior: 'smooth'
                    });
                }
            });
        });
        
        // Highlight active section on scroll
        window.addEventListener('scroll', function() {
            const sections = document.querySelectorAll('.documentation-content section');
            let currentSection = '';
            
            sections.forEach(section => {
                const sectionTop = section.offsetTop - 120;
                const sectionHeight = section.offsetHeight;
                
                if (window.pageYOffset >= sectionTop && window.pageYOffset < sectionTop + sectionHeight) {
                    currentSection = section.getAttribute('id');
                }
            });
            
            if (currentSection) {
                docLinks.forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === '#' + currentSection) {
                        link.classList.add('active');
                    }
                });
            }
        });
    }
});
