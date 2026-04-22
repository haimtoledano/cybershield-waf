
type RequestOptions = RequestInit & {
    params?: Record<string, string>;
};

let authToken: string | null = localStorage.getItem('waf_token');
let onAuthError: (() => void) | null = null;
let tokenVersion = 0; // Track token changes to prevent stale-401 race conditions
const BASE_URL = import.meta.env?.VITE_API_URL || `http://${window.location.hostname}:8555`;
export const api = {
    setToken: (token: string | null) => {
        authToken = token;
        tokenVersion++; // Invalidate any in-flight requests using older tokens
        if (token) {
            localStorage.setItem('waf_token', token);
        } else {
            localStorage.removeItem('waf_token');
        }
    },
    
    setOnAuthError: (callback: () => void) => {
        onAuthError = callback;
    },

    request: async (endpoint: string, options: RequestOptions = {}) => {
        let url: URL;
        if (endpoint.startsWith('http')) {
            url = new URL(endpoint);
        } else {
            url = new URL(`${BASE_URL}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`);
        }
        
        if (options.params) {
            Object.keys(options.params).forEach(key => 
                url.searchParams.append(key, options.params![key])
            );
        }

        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            ...(options.headers as Record<string, string>),
        };

        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }

        // Capture the token version at request time so we can detect stale responses
        const requestTokenVersion = tokenVersion;

        try {
            const response = await fetch(url.toString(), {
                ...options,
                headers,
            });

            if (response.status === 401 && !url.pathname.endsWith('/api/auth/login')) {
                // Only trigger auth error if the token hasn't been changed since this
                // request was made. This prevents stale 401 responses (from old tokens)
                // from logging out a user who just set a fresh valid token.
                if (onAuthError && requestTokenVersion === tokenVersion) {
                    onAuthError();
                }
                return response;
            }

            return response;
        } catch (error) {
            console.error('API Request Error:', error);
            throw error;
        }
    },

    get: (endpoint: string, options: RequestOptions = {}) => 
        api.request(endpoint, { ...options, method: 'GET' }),

    post: (endpoint: string, body?: any, options: RequestOptions = {}) => 
        api.request(endpoint, { 
            ...options, 
            method: 'POST', 
            body: body ? JSON.stringify(body) : undefined 
        }),

    put: (endpoint: string, body?: any, options: RequestOptions = {}) => 
        api.request(endpoint, { 
            ...options, 
            method: 'PUT', 
            body: body ? JSON.stringify(body) : undefined 
        }),

    patch: (endpoint: string, body?: any, options: RequestOptions = {}) => 
        api.request(endpoint, { 
            ...options, 
            method: 'PATCH', 
            body: body ? JSON.stringify(body) : undefined 
        }),

    delete: (endpoint: string, options: RequestOptions = {}) => 
        api.request(endpoint, { ...options, method: 'DELETE' }),
};
