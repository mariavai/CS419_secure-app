//dashboard.js
let selectedDocID = null;

document.addEventListener('DOMContentLoaded', () => {
    const role = localStorage.getItem('userRole');
    if (role === 'admin') {
        document.getElementById('admin-tabs').classList.remove('hidden');
        loadUsers();    //allow admins to manage users
    }
    loadFiles();
});

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    if (tabName === 'files') {
        document.getElementById('view-files').classList.remove('hidden');
        document.getElementById('view-users').classList.add('hidden');
    } else {
        document.getElementById('view-files').classList.add('hidden');
        document.getElementById('view-users').classList.remove('hidden');
    }
}

function selectRow(element, docID) {
    document.querySelectorAll('.file-row').forEach(row => row.classList.remove('selected'));
    element.classList.add('selected');
    selectedDocID = docID;
    document.getElementById('btn-download').disabled = false;
}

async function loadFiles() {
    try {
        const res = await fetch('/findUserFileList');
        const files = await res.json();
        
        const container = document.getElementById('file-container');
        container.innerHTML = '';

        files.forEach(f => {
            const row = document.createElement('div');
            row.className = 'file-row';
            row.onclick = () => selectRow(row, f.docID);
            const dateStr = new Date(f.createdAt * 1000).toLocaleDateString();

            row.innerHTML = `
                <span>${f.fileName}</span>
                <span>${f.owner}</span>
                <span>${dateStr}</span>
                <span>
                    <button class="btn small-btn" onclick="openShareModal('${f.docID}', event)">Share</button>
                    <button class="btn small-btn" onclick="openAuditModal('${f.docID}', event)">History</button>
                    <button class="danger-btn small-btn" onclick="deleteDocument('${f.docID}', event)">Delete</button>
                </span>
            `;



            container.appendChild(row);
            
        });
    } catch (e) {
        console.error("Failed to load files");
    }
}

async function loadUsers() {
    try {
        const res = await fetch('/findUsersList');
        const users = await res.json();
        
        const container = document.getElementById('user-container');
        container.innerHTML = '';
        
        users.forEach(u => {
            const row = document.createElement('div');
            row.className = 'file-row';
            row.innerHTML = `
                <span>${u.username}</span>
                <span>${u.role}</span>
                <span>Active</span>
            `;
            container.appendChild(row);
        });
    } catch (e) {
        console.error("Failed to load users", e);
    }
}

function downloadSelected() {
    if (selectedDocID) {
        window.location.href = `/download/${selectedDocID}`;
    }
}

async function uploadFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch('/upload', {
        method: 'POST',
        body: formData
    });
    const data = await res.json();
    if (data.success) {
        loadFiles();
    } else {
        alert("Upload failed. Ensure you have permissions.");
    }
}

async function logout() {
    await fetch('/logout', { method: 'POST' });
    localStorage.removeItem('userRole');
    window.location.href = '/';
}

async function deleteDocument(docID, event) {
    event.stopPropagation(); // prevent row selection

    if (!confirm("Are you sure you want to delete this document? This cannot be undone.")) {
        return;
    }

    try {
        const res = await fetch('/deleteDocument', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ docId: docID })
        });

        const data = await res.json();

        if (res.ok) {
            showToast("Document deleted successfully!", "success");
            loadFiles(); // refresh list
        } else {
            showToast(data.error || "Delete failed", "error");
        }
    } catch (err) {
        showToast("Server connection failed.", "error");
    }
}

function showToast(message, type = "success") {
    const container = document.getElementById("toast-container");
    if (!container) return alert(message);

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add("fade-out");
        setTimeout(() => toast.remove(), 300);
    }, 2000);
}
function openPasswordModal() {
    document.getElementById("password-modal").classList.remove("hidden");
}

function closePasswordModal() {
    document.getElementById("password-modal").classList.add("hidden");
}

async function submitPasswordChange() {
    const oldPass = document.getElementById("old-password").value;
    const newPass = document.getElementById("new-password").value;
    const confirmPass = document.getElementById("confirm-password").value;

    if (newPass !== confirmPass) {
        alert("New passwords do not match.");
        return;
    }

    const res = await fetch("/changePassword", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            oldPassword: oldPass,
            newPassword: newPass
        })
    });

    const data = await res.json();

    if (res.ok) {
        alert("Password updated successfully.");
        closePasswordModal();
    } else {
        alert(data.error || "Password update failed.");
    }

}

function openAuditModal(docID, event) {
    event.stopPropagation(); // prevent row selection

    fetch(`/document/${docID}/audit`)
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById("audit-info");

            if (data.error) {
                container.innerHTML = `<p class="error">${data.error}</p>`;
            } else {
                // Build audit log HTML
                let auditHTML = `
                    <p><strong>File:</strong> ${data.fileName}</p>
                    <p><strong>Owner:</strong> ${data.owner}</p>
                    <p><strong>Created:</strong> ${new Date(data.createdAt * 1000).toLocaleString()}</p>
                    <hr>
                    <h4>Versions</h4>
                `;

                data.versions.forEach(v => {
                    auditHTML += `
                        <div class="audit-entry">
                            <p><strong>Version:</strong> ${v.version}</p>
                            <p><strong>Uploaded By:</strong> ${v.uploadedBy}</p>
                            <p><strong>Timestamp:</strong> ${new Date(v.timestamp * 1000).toLocaleString()}</p>
                        </div>
                        <hr>
                    `;
                });

                auditHTML += `<h4>Audit Log</h4>`;

                data.auditLog.forEach(a => {
                    auditHTML += `
                        <div class="audit-entry">
                            <p><strong>User:</strong> ${a.user}</p>
                            <p><strong>Action:</strong> ${a.action}</p>
                            <p><strong>Timestamp:</strong> ${new Date(a.timestamp * 1000).toLocaleString()}</p>
                        </div>
                        <hr>
                    `;
                });

                container.innerHTML = auditHTML;
            }

            document.getElementById("audit-modal").classList.remove("hidden");
        })
        .catch(() => {
            document.getElementById("audit-info").innerHTML = "<p class='error'>Failed to load audit log.</p>";
            document.getElementById("audit-modal").classList.remove("hidden");
        });
}

function closeAuditModal() {
    document.getElementById("audit-modal").classList.add("hidden");
}

let currentShareDocID = null;

function openShareModal(docID, event) {
    event.stopPropagation();
    currentShareDocID = docID;

    fetch(`/document/${docID}/audit`)
        .then(res => res.json())
        .then(data => {
            const list = document.getElementById("share-access-list");
            list.innerHTML = "";

            const shared = data.sharedWith || {};

            if (Object.keys(shared).length === 0) {
                list.innerHTML = "<p>No shared users.</p>";
            } else {
                list.innerHTML = "";
                Object.entries(shared).forEach(([user, role]) => {
                    const row = document.createElement("div");
                    row.className = "share-access-row";
                    row.innerHTML = `
                        <span>${user} — ${role}</span>
                        <button class="danger-btn small-btn" onclick="unshareUser('${user}')">Unshare</button>
                    `;
                    list.appendChild(row);
                });
            }

            document.getElementById("share-modal").classList.remove("hidden");
        });
}


function closeShareModal() {
    document.getElementById("share-modal").classList.add("hidden");
}

async function submitShare() {
    const targetUser = document.getElementById("share-username").value;
    const role = document.getElementById("share-role").value;

    const res = await fetch("/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            docId: currentShareDocID,
            targetUser,
            role
        })
    });

    const data = await res.json();

    if (res.ok) {
        showToast("Document shared!", "success");
        closeShareModal();
        loadFiles();
    } else {
        showToast(data.error || "Share failed", "error");
    }
}

async function unshareUser(username) {
    const res = await fetch("/unshare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            docId: currentShareDocID,
            targetUser: username
        })
    });

    const data = await res.json();

    if (res.ok) {
        showToast("Access removed", "success");

        // Reload modal so the list updates
        openShareModal(currentShareDocID, { stopPropagation: () => {} });

        // Refresh file list
        loadFiles();
    } else {
        showToast(data.error || "Unshare failed", "error");
    }
}

