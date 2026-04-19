function toggleView() {
    document.getElementById('login-view').classList.toggle('hidden');
    document.getElementById('register-view').classList.toggle('hidden');
    document.getElementById('login-form').reset();
    document.getElementById('register-form').reset();
}

function showToast(message, type = 'error') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('fade-out');
        toast.addEventListener('animationend', () => toast.remove());
    }, 4000);
}

//login
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const btn = e.target.querySelector('button');
    btn.disabled = true;

    const username = document.getElementById('login-user').value;
    const password = document.getElementById('login-pass').value;

    try {
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                'username': username, 
                'password': password })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            localStorage.setItem('userRole', data.role || 'user'); 
            localStorage.setItem('username', username);
            window.location.href = '/dashboard';
        } else {
            showToast(data.error || "Invalid credentials", "error");
        }
    } catch (err) {
        showToast("Server connection failed.", "error");
    } finally {
        btn.disabled = false;
    }
});

//register
document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const btn = e.target.querySelector('button');
    btn.disabled = true; 

    const username = document.getElementById('reg-user').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-pass').value;
    const confirmPassword = document.getElementById('reg-pass-confirm').value;


    try {
        const res = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                'username': username, 
                'email': email, 
                'password': password,
                'confirm_password': confirmPassword })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            showToast("Account created successfully! Please log in.", "success");
            toggleView(); 
        } else {
            showToast(data.error || "Registration failed", "error");
        }
    } catch (err) {
        showToast("Server connection failed.", "error");
    } finally {
        btn.disabled = false;
    }
});