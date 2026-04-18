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
            const dateStr = new Date(f.uploadDate * 1000).toLocaleDateString();
            
            row.innerHTML = `
                <span>${f.fileName}</span>
                <span>${f.owner}</span>
                <span>${dateStr}</span>
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