
type RequestOptions = RequestInit & {
    params?: Record<string, string>;
};

let authToken: string | null = localStorage.getItem('waf_token');
let onAuthError: (() => void) | null = null;
const BASE_URL = 'http://localhost:8555';

export const api = {
    setToken: (token: string | null) => {
        authToken = token;
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

        try {
            const response = await fetch(url.toString(), {
                ...options,
                headers,
            });

            if (response.status === 401 && !url.pathname.endsWith('/api/auth/login')) {
                if (onAuthError) onAuthError();
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

    delete: (endpoint: string, options: RequestOptions = {}) => 
        api.request(endpoint, { ...options, method: 'DELETE' }),
};
