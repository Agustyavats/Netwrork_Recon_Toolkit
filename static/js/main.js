/**
 * Network Recon Toolkit — client-side helpers
 */

document.addEventListener("DOMContentLoaded", function () {
    const scanForm = document.getElementById("scanForm");
    const scanBtn = document.getElementById("scanBtn");

    if (scanForm && scanBtn) {
        scanForm.addEventListener("submit", function () {
            scanBtn.disabled = true;
            scanBtn.textContent = "Scanning…";
            showLoadingOverlay();
        });
    }
});

function showLoadingOverlay() {
    let overlay = document.getElementById("loadingOverlay");
    if (!overlay) {
        overlay = document.createElement("div");
        overlay.id = "loadingOverlay";
        overlay.className = "loading-overlay active";
        overlay.innerHTML =
            '<div class="spinner"></div><p>Running reconnaissance scan…</p>';
        document.body.appendChild(overlay);
    } else {
        overlay.classList.add("active");
    }
}
