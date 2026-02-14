/**
 * Auth Test GUI - Vanilla JS
 * OAuth & Session Authentication Tester
 */

const CONFIG = {
    BACKEND_URL: 'http://localhost:8090',
    SESSION_COOKIE_NAME: '__Host-session',
    PROTECTED_ENDPOINT: '/api/ping',
    LOGOUT_ENDPOINT: '/auth/logout',
    LOGOUT_ALL_ENDPOINT: '/auth/logout-all'
};

// ===== Utility Functions =====

/**
 * Get a specific cookie value by name
 */
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

/**
 * Get all cookies as an object
 */
function getAllCookies() {
    const cookies = {};
    const cookieString = document.cookie;

    if (!cookieString) return cookies;

    cookieString.split(';').forEach(cookie => {
        const [name, ...valueParts] = cookie.trim().split('=');
        if (name) {
            cookies[name] = valueParts.join('=');
        }
    });

    return cookies;
}

/**
 * Try to decode a JWT-like token
 */
function decodeToken(token) {
    if (!token) return null;

    try {
        // Try base64 decode (for JWT-like tokens)
        const parts = token.split('.');
        if (parts.length === 3) {
            const decode = (str) => {
                try {
                    return JSON.parse(atob(str.replace(/-/g, '+').replace(/_/g, '/')));
                } catch {
                    return null;
                }
            };

            return {
                header: decode(parts[0]),
                payload: decode(parts[1]),
                signature: '[signature]'
            };
        }

        // Try simple base64 decode
        try {
            return { decoded: atob(token) };
        } catch {
            return { raw: token };
        }
    } catch (e) {
        return { raw: token, error: e.message };
    }
}

/**
 * Format JSON with syntax highlighting
 */
function formatJSON(obj) {
    if (obj === null) return '<span class="json-null">null</span>';
    if (obj === undefined) return '<span class="json-null">undefined</span>';

    const json = JSON.stringify(obj, null, 2);
    return json
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
        .replace(/: "([^"]*)"/g, ': <span class="json-string">"$1"</span>')
        .replace(/: (\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
        .replace(/: (true|false)/g, ': <span class="json-boolean">$1</span>')
        .replace(/: null/g, ': <span class="json-null">null</span>');
}

/**
 * Show a message in the message area
 */
function showMessage(message, type = 'info') {
    const messageArea = document.getElementById('message-area');
    if (!messageArea) return;

    messageArea.className = `message-area message-${type}`;
    messageArea.textContent = message;
    messageArea.classList.remove('hidden');

    // Auto-hide after 5 seconds
    setTimeout(() => {
        messageArea.classList.add('hidden');
    }, 5000);
}

/**
 * Update the cookie inspector panel
 */
function updateCookiePanel() {
    const panel = document.getElementById('cookie-panel');
    if (!panel) return;

    const cookies = getAllCookies();
    const sessionCookie = getCookie(CONFIG.SESSION_COOKIE_NAME);
    const decodedSession = sessionCookie ? decodeToken(sessionCookie) : null;

    const data = {
        allCookies: cookies,
        sessionCookie: sessionCookie,
        decodedSession: decodedSession,
        cookieCount: Object.keys(cookies).length,
        hasSession: !!sessionCookie
    };

    panel.innerHTML = `<pre>${formatJSON(data)}</pre>`;
}

/**
 * Update authentication status display
 */
function updateAuthStatus(status, message = '') {
    const statusEl = document.getElementById('auth-status');
    const sessionEl = document.getElementById('session-cookie');

    if (statusEl) {
        statusEl.className = `status-badge status-${status}`;
        statusEl.textContent = message || (status === 'authenticated' ? 'Authenticated' : 'Unauthenticated');
    }

    if (sessionEl) {
        const sessionCookie = getCookie(CONFIG.SESSION_COOKIE_NAME);
        sessionEl.textContent = sessionCookie ? `${sessionCookie.substring(0, 32)}...` : '-';
        sessionEl.title = sessionCookie || 'No session cookie found';
    }
}

// ===== API Functions =====

/**
 * Check if user is authenticated by calling protected endpoint
 */
async function checkAuth() {
    updateAuthStatus('checking', 'Checking...');

    try {
        const response = await fetch(`${CONFIG.BACKEND_URL}${CONFIG.PROTECTED_ENDPOINT}`, {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            updateAuthStatus('authenticated', 'Authenticated');
            return true;
        } else {
            updateAuthStatus('unauthenticated', 'Unauthenticated');
            return false;
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        updateAuthStatus('unauthenticated', 'Connection Error');
        return false;
    }
}

/**
 * Call the protected API endpoint
 */
async function callProtectedAPI() {
    const responsePanel = document.getElementById('api-response');
    const statusEl = document.getElementById('response-status');
    const timeEl = document.getElementById('response-time');
    const bodyEl = document.getElementById('response-body');
    const button = document.getElementById('call-protected');

    if (button) button.disabled = true;

    const startTime = performance.now();

    try {
        const response = await fetch(`${CONFIG.BACKEND_URL}${CONFIG.PROTECTED_ENDPOINT}`, {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });

        const endTime = performance.now();
        const duration = (endTime - startTime).toFixed(0);

        const responseData = await response.json().catch(() => ({
            status: response.status,
            statusText: response.statusText
        }));

        // Update UI
        statusEl.className = `status-code ${response.ok ? 'status-success' : 'status-error'}`;
        statusEl.textContent = `${response.status} ${response.statusText}`;
        timeEl.textContent = `${duration}ms`;
        bodyEl.innerHTML = formatJSON(responseData);
        responsePanel.classList.remove('hidden');

        // Update auth status based on response
        if (response.ok) {
            updateAuthStatus('authenticated');
        } else if (response.status === 401) {
            updateAuthStatus('unauthenticated');
        }

    } catch (error) {
        const endTime = performance.now();
        const duration = (endTime - startTime).toFixed(0);

        statusEl.className = 'status-code status-error';
        statusEl.textContent = 'Network Error';
        timeEl.textContent = `${duration}ms`;
        bodyEl.innerHTML = formatJSON({
            error: error.message,
            hint: 'Make sure the backend is running at ' + CONFIG.BACKEND_URL
        });
        responsePanel.classList.remove('hidden');
    } finally {
        if (button) button.disabled = false;
    }
}

/**
 * Logout current session
 */
async function logout() {
    const button = document.getElementById('logout-btn');
    if (button) button.disabled = true;

    try {
        const response = await fetch(`${CONFIG.BACKEND_URL}${CONFIG.LOGOUT_ENDPOINT}`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            showMessage('Logged out successfully', 'success');
            updateAuthStatus('unauthenticated');
            updateCookiePanel();

            // Clear response panel
            const responsePanel = document.getElementById('api-response');
            if (responsePanel) responsePanel.classList.add('hidden');

            // Redirect to login after a short delay
            setTimeout(() => {
                window.location.href = '/?message=logged-out';
            }, 1500);
        } else {
            const data = await response.json().catch(() => ({}));
            showMessage(data.message || `Logout failed: ${response.status}`, 'error');
        }
    } catch (error) {
        showMessage(`Logout error: ${error.message}`, 'error');
    } finally {
        if (button) button.disabled = false;
    }
}

/**
 * Logout all sessions
 */
async function logoutAll() {
    const button = document.getElementById('logout-all-btn');
    if (button) button.disabled = true;

    try {
        const response = await fetch(`${CONFIG.BACKEND_URL}${CONFIG.LOGOUT_ALL_ENDPOINT}`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            showMessage('Logged out from all sessions', 'success');
            updateAuthStatus('unauthenticated');
            updateCookiePanel();

            // Clear response panel
            const responsePanel = document.getElementById('api-response');
            if (responsePanel) responsePanel.classList.add('hidden');

            // Redirect to login after a short delay
            setTimeout(() => {
                window.location.href = 'index.html?message=logged-out-all';
            }, 1500);
        } else {
            const data = await response.json().catch(() => ({}));
            showMessage(data.message || `Logout all failed: ${response.status}`, 'error');
        }
    } catch (error) {
        showMessage(`Logout all error: ${error.message}`, 'error');
    } finally {
        if (button) button.disabled = false;
    }
}

// ===== Page Initialization =====

/**
 * Initialize login page
 */
function initLoginPage() {
    // Check for messages in URL
    const params = new URLSearchParams(window.location.search);
    const message = params.get('message');

    if (message === 'logged-out') {
        showMessage('Logged out successfully', 'success');
    } else if (message === 'logged-out-all') {
        showMessage('Logged out from all sessions', 'success');
    }
}

/**
 * Initialize dashboard page
 */
async function initDashboardPage() {
    // First check if user is authenticated
    const isAuth = await checkAuth();

    if (!isAuth) {
        showMessage('Not authenticated. Redirecting to login...', 'error');
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 2000);
        return;
    }

    // Update cookie panel
    updateCookiePanel();

    // Set up event listeners
    document.getElementById('call-protected')?.addEventListener('click', callProtectedAPI);
    document.getElementById('logout-btn')?.addEventListener('click', logout);
    document.getElementById('logout-all-btn')?.addEventListener('click', logoutAll);
    document.getElementById('refresh-cookies')?.addEventListener('click', () => {
        updateCookiePanel();
        showMessage('Cookies refreshed', 'info');
    });
}

/**
 * Main initialization
 */
function init() {
    const path = window.location.pathname;

    if (path.endsWith('index.html') || path.endsWith('/') || path === '') {
        initLoginPage();
    } else if (path.endsWith('dashboard.html')) {
        initDashboardPage();
    }
}

// Run initialization when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
