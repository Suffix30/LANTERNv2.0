document.addEventListener('DOMContentLoaded', function() {
  var tabsInfo = document.getElementById('tabs-info');
  var statusDiv = document.getElementById('status');
  
  chrome.tabs.query({}, function(tabs) {
    if (chrome.runtime.lastError) {
      tabsInfo.textContent = 'Error: ' + chrome.runtime.lastError.message;
    } else if (tabs && tabs.length > 0) {
      tabsInfo.textContent = 'Tracking ' + tabs.length + ' open tabs';
    } else {
      tabsInfo.textContent = 'No tabs found';
    }
  });
  
  document.getElementById('sync').addEventListener('click', function() {
    chrome.tabs.query({}, function(tabs) {
      if (tabs && tabs.length > 0) {
        var state = {
          timestamp: new Date().toISOString(),
          tabs: []
        };
        for (var i = 0; i < tabs.length; i++) {
          state.tabs.push({
            url: tabs[i].url,
            title: tabs[i].title,
            active: tabs[i].active
          });
        }
        chrome.storage.local.set({ browserState: state }, function() {
          statusDiv.textContent = 'Saved ' + tabs.length + ' tabs at ' + new Date().toLocaleTimeString();
          statusDiv.className = 'status connected';
        });
      } else {
        statusDiv.textContent = 'No tabs to save';
      }
    });
  });
  
  document.getElementById('copy').addEventListener('click', function() {
    chrome.tabs.query({}, function(tabs) {
      if (tabs && tabs.length > 0) {
        var urls = '';
        for (var i = 0; i < tabs.length; i++) {
          urls += tabs[i].url + '\n';
        }
        navigator.clipboard.writeText(urls.trim()).then(function() {
          statusDiv.textContent = 'Copied ' + tabs.length + ' URLs to clipboard';
          statusDiv.className = 'status connected';
        }).catch(function(err) {
          statusDiv.textContent = 'Copy failed: ' + err;
        });
      }
    });
  });
});
