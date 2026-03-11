const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('basilisk', {
    // IPC: renderer → main
    send: (channel, ...args) => {
        const allowed = ['window:minimize', 'window:maximize', 'window:close'];
        if (allowed.includes(channel)) ipcRenderer.send(channel, ...args);
    },
    invoke: (channel, ...args) => {
        const allowed = [
            'dialog:exportReport', 'dialog:saveFile', 'window:getToken', 'window:getPort',
            'backend:multiturnModules', 'backend:evolutionOperators', 'backend:moduleList',
            'shell:openExternal',
        ];
        if (allowed.includes(channel)) return ipcRenderer.invoke(channel, ...args);
        return Promise.reject(new Error(`IPC channel not allowed: ${channel}`));
    },

    // IPC: main → renderer
    onBackendLog: (cb) => ipcRenderer.on('backend-log', (_, msg) => cb(msg)),
    onBackendError: (cb) => ipcRenderer.on('backend-error', (_, msg) => cb(msg)),

    // Helper to get token (internal use)
    _getToken: () => ipcRenderer.invoke('window:getToken'),

    // Report export shortcut
    report: {
        export: async (sessionId, format) => {
            try {
                const token = await ipcRenderer.invoke('window:getToken');
                const resp = await fetch(`http://127.0.0.1:8741/api/report/${sessionId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Basilisk-Token': token
                    },
                    body: JSON.stringify({ format, open_browser: true }),
                });
                const data = await resp.json();
                if (data.content) {
                    const ext = format === 'html' ? 'html' : format === 'sarif' ? 'sarif' : format === 'markdown' ? 'md' : 'json';
                    const result = await ipcRenderer.invoke('dialog:saveFile', {
                        content: typeof data.content === 'string' ? data.content : JSON.stringify(data.content, null, 2),
                        defaultName: `basilisk_report_${Date.now()}.${ext}`,
                        filters: [{ name: `${format.toUpperCase()} Report`, extensions: [ext] }],
                    });
                    return result;
                }
                return { success: false, error: data.error || 'No content' };
            } catch (e) {
                return { success: false, error: e.message };
            }
        },
    },

    // API key management via electron-store (if available)
    apiKeys: {
        set: async (provider, key) => {
            try {
                const token = await ipcRenderer.invoke('window:getToken');
                await fetch(`http://127.0.0.1:8741/api/settings/apikey`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Basilisk-Token': token
                    },
                    body: JSON.stringify({ provider, key }),
                });
            } catch (e) { /* best effort */ }
        },
    },

    // Multi-turn module details
    modules: {
        getMultiturn: () => ipcRenderer.invoke('backend:multiturnModules'),
        getAll: () => ipcRenderer.invoke('backend:moduleList'),
    },

    // Evolution engine info
    evolution: {
        getOperators: () => ipcRenderer.invoke('backend:evolutionOperators'),
    },

    // Open external URL safely
    openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
});

// Also expose as window.api for compatibility
contextBridge.exposeInMainWorld('api', {
    send: (channel, ...args) => ipcRenderer.send(channel, ...args),
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
});
