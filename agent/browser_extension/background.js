const STATE_FILE_ENDPOINT = 'http://localhost:8765/browser_state';
const UPDATE_INTERVAL = 5000;

async function gatherBrowserState() {
    const tabs = await chrome.tabs.query({});
    
    const state = {
        timestamp: new Date().toISOString(),
        tabs: tabs.map(tab => ({
            id: tab.id,
            url: tab.url,
            title: tab.title,
            active: tab.active,
            windowId: tab.windowId,
        })),
        activeTab: tabs.find(t => t.active) || null,
    };
    
    return state;
}

async function sendStateToAgent() {
    try {
        const state = await gatherBrowserState();
        
        await fetch(STATE_FILE_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(state),
        });
        
        console.log('[Agent BLACK] Browser state sent:', state.tabs.length, 'tabs');
    } catch (error) {
        console.log('[Agent BLACK] Agent not running, saving locally');
        chrome.storage.local.set({ browserState: await gatherBrowserState() });
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
        sendStateToAgent();
    }
});

chrome.tabs.onActivated.addListener(() => {
    sendStateToAgent();
});

chrome.tabs.onRemoved.addListener(() => {
    sendStateToAgent();
});

setInterval(sendStateToAgent, UPDATE_INTERVAL);

sendStateToAgent();
