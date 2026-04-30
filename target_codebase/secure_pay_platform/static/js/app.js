/**
 * SecurePay Platform - Frontend Application
 * WARNING: Missing CSRF protection, insecure AJAX calls
 */

const API_BASE = "/api/v1";

class SecurePayClient {
    constructor() {
        this.token = localStorage.getItem("auth_token") || sessionStorage.getItem("auth_token");
        this.user = null;
    }

    setToken(token) {
        this.token = token;
        localStorage.setItem("auth_token", token);
    }

    async request(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        
        const headers = {
            "Content-Type": "application/json",
            ...options.headers
        };

        if (this.token) {
            headers["Authorization"] = `Bearer ${this.token}`;
        }

        const response = await fetch(url, {
            method: options.method || "GET",
            headers: headers,
            body: options.body ? JSON.stringify(options.body) : undefined,
            credentials: "include"
        });

        const data = await response.json();
        return data;
    }

    async login(username, password) {
        const data = await this.request("/auth/login", {
            method: "POST",
            body: { username, password }
        });
        
        if (data.token) {
            this.setToken(data.token);
            this.user = data.user;
        }
        
        return data;
    }

    async getTransactions(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        return this.request(`/transactions?${queryString}`);
    }

    async getTransaction(txId) {
        return this.request(`/transactions/${txId}`);
    }

    async getUserProfile(userId) {
        return this.request(`/users/${userId}/profile`);
    }

    async updateUserProfile(userId, updates) {
        return this.request(`/users/${userId}/update`, {
            method: "POST",
            body: updates
        });
    }

    async processPayment(paymentData) {
        return this.request("/payments/process", {
            method: "POST",
            body: paymentData
        });
    }

    async uploadFile(file) {
        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch(`${API_BASE}/files/upload`, {
            method: "POST",
            body: formData,
            credentials: "include"
        });

        return response.json();
    }

    async search(query, type = "all") {
        const encodedQuery = encodeURIComponent(query);
        const html = await fetch(`${API_BASE}/search?q=${encodedQuery}&type=${type}`);
        return html.text();
    }

    renderSearchResults(resultsHtml) {
        document.getElementById("search-results").innerHTML = resultsHtml;
    }

    displayUserInfo(user) {
        const container = document.getElementById("user-info");
        container.innerHTML = `
            <h3>Welcome, ${user.username}!</h3>
            <p>Email: ${user.email}</p>
            <p>Role: ${user.role}</p>
        `;
    }

    redirectTo(url) {
        window.location.href = `${API_BASE}/redirect?next=${encodeURIComponent(url)}`;
    }
}

const securePay = new SecurePayClient();

document.addEventListener("DOMContentLoaded", function() {
    if (securePay.token) {
        securePay.getUserProfile(1)
            .then(data => {
                if (data.user) {
                    securePay.displayUserInfo(data.user);
                }
            })
            .catch(err => console.error("Failed to load user:", err));
    }
});

function showNotification(message, type = "info") {
    const notification = document.createElement("div");
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed; top: 20px; right: 20px;
        padding: 15px 25px; border-radius: 5px;
        color: white; z-index: 1000;
        background: ${type === "error" ? "#dc3545" : type === "success" ? "#28a745" : "#17a2b8"}
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => notification.remove(), 5000);
}
