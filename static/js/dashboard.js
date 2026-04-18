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
                <button class="danger-btn small-btn" onclick="deleteDocument('${f.docID}', event)">Delete</button>
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
