// TrustVault Interactive UI Helpers

function openShareModal(docId, docTitle) {
  const modal = document.getElementById('shareModal');
  const modalTitle = document.getElementById('shareModalDocTitle');
  const docIdInput = document.getElementById('shareModalDocId');
  const form = document.getElementById('shareForm');

  if (modal && modalTitle && docIdInput && form) {
    modalTitle.textContent = docTitle;
    docIdInput.value = docId;
    form.action = `/share/${docId}`;
    modal.classList.add('active');
  }
}

function closeShareModal() {
  const modal = document.getElementById('shareModal');
  if (modal) {
    modal.classList.remove('active');
  }
}

// Close modal on click outside
window.addEventListener('click', (e) => {
  const modal = document.getElementById('shareModal');
  if (modal && e.target === modal) {
    modal.classList.remove('active');
  }
});

function copyToClipboard(text, element) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = element.getAttribute('title') || 'Click to copy';
    element.setAttribute('title', 'Copied!');
    element.style.color = '#00f0ff';
    setTimeout(() => {
      element.setAttribute('title', originalText);
      element.style.color = '';
    }, 1500);
  });
}

// Real-time verification button handling
async function runLiveVerification(button) {
  const originalHtml = button.innerHTML;
  button.innerHTML = 'Verifying SHA-256 Chain...';
  button.disabled = true;

  try {
    const response = await fetch('/admin/verify-audit', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });

    const data = await response.json();
    if (data.valid) {
      alert(`[VERIFIED SECURE]\n${data.message}\nTotal Records: ${data.count}\nHead Hash: ${data.head_hash}`);
      window.location.reload();
    } else {
      alert(`[SECURITY INTEGRITY ALERT!]\n${data.reason}\nTampered ID: ${data.tampered_id}\nType: ${data.error_type}`);
      window.location.reload();
    }
  } catch (err) {
    alert('Verification request failed. Check server logs.');
  } finally {
    button.innerHTML = originalHtml;
    button.disabled = false;
  }
}
