document.addEventListener('DOMContentLoaded', () => {
  const btnAnalyze = document.getElementById('btn-analyze');
  const btnGrab = document.getElementById('btn-grab');
  const inputText = document.getElementById('input-text');
  
  const loadingContainer = document.getElementById('loading-container');
  const resultsContainer = document.getElementById('results-container');
  
  const verdictBadge = document.getElementById('verdict-badge');
  const scoreVal = document.getElementById('score-val');
  const entityName = document.getElementById('entity-name');
  const summaryText = document.getElementById('summary-text');
  const actionsList = document.getElementById('actions-list');
  const reportLink = document.getElementById('report-link');

  const BACKEND_URL = "https://phishing-detector-self-five.vercel.app/api/analyze-v2";

  // 1. Restore previous scan state / last report if popup closed
  restorePreviousState();

  // 2. Auto-grab selected text from current tab if input is empty
  autoGrabSelectedText();

  btnGrab.addEventListener('click', autoGrabSelectedText);

  btnAnalyze.addEventListener('click', () => {
    const text = inputText.value.trim();
    if (!text) {
      alert("Please paste job offer text or click AUTO-GRAB to capture highlighted text.");
      return;
    }
    runOSINTScan(text);
  });

  function restorePreviousState() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['input_text', 'last_report', 'is_scanning'], (saved) => {
        if (saved.input_text && !inputText.value) {
          inputText.value = saved.input_text;
        }

        if (saved.is_scanning) {
          loadingContainer.classList.remove('hidden');
          resultsContainer.classList.add('hidden');
          btnAnalyze.disabled = true;
        } else if (saved.last_report) {
          renderReport(saved.last_report);
        }
      });
    }
  }

  function autoGrabSelectedText() {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.scripting) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || !tabs[0]) return;
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: () => window.getSelection().toString()
        }, (results) => {
          if (results && results[0] && results[0].result) {
            const selected = results[0].result.trim();
            if (selected) {
              inputText.value = selected;
              if (chrome.storage && chrome.storage.local) {
                chrome.storage.local.set({ input_text: selected });
              }
            }
          }
        });
      });
    }
  }

  async function runOSINTScan(text) {
    // Save state to chrome.storage
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ is_scanning: true, input_text: text });
    }

    loadingContainer.classList.remove('hidden');
    resultsContainer.classList.add('hidden');
    btnAnalyze.disabled = true;

    try {
      const formData = new FormData();
      formData.append('text', text);
      formData.append('user_id', 'chrome_extension_user');

      const res = await fetch(BACKEND_URL, {
        method: 'POST',
        body: formData
      });

      if (!res.ok) {
        throw new Error(`HTTP Error ${res.status}`);
      }

      const data = await res.json();

      if (data.status === 'error') {
        alert("Scan Error: " + (data.message || "Failed to analyze offer"));
        return;
      }

      // Save complete report payload to chrome.storage
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ is_scanning: false, last_report: data });
      }

      renderReport(data);
    } catch (err) {
      console.error(err);
      alert("OSINT Pipeline Request Failed. Please check network connection.");
    } finally {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ is_scanning: false });
      }
      loadingContainer.classList.add('hidden');
      btnAnalyze.disabled = false;
    }
  }

  function renderReport(data) {
    const report = data.report || {};
    const execSummary = report.executive_summary || {};
    const userReport = report.user_facing_report || {};
    const takeaway = execSummary.one_sentence_takeaway || {};

    const verdict = (execSummary.verdict || "inconclusive").toLowerCase();
    const score = execSummary.confidence_score !== undefined ? execSummary.confidence_score : "--";
    const entity = report.metadata?.target_entity || data.extracted_entities?.organization_name || "Target Entity";
    const summary = takeaway.en || takeaway.user_language || "OSINT analysis completed.";

    // Render Badge & Color
    verdictBadge.className = 'verdict-badge';
    if (verdict === 'high_risk' || verdict === 'likely_scam') {
      verdictBadge.textContent = '🔴 LIKELY SCAM';
      verdictBadge.classList.add('red');
    } else if (verdict === 'suspicious' || verdict === 'medium_risk') {
      verdictBadge.textContent = '🟡 SUSPICIOUS OFFER';
      verdictBadge.classList.add('amber');
    } else {
      verdictBadge.textContent = '🟢 VERIFIED LOW RISK';
      verdictBadge.classList.add('green');
    }

    scoreVal.textContent = `${score}/100`;
    entityName.textContent = entity;
    summaryText.textContent = summary;

    // Render Actions List
    actionsList.innerHTML = '';
    const actions = userReport.what_you_should_do || [];
    if (actions.length > 0) {
      actions.slice(0, 3).forEach(act => {
        const li = document.createElement('li');
        li.textContent = act;
        actionsList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.textContent = "Verify company contact details before proceeding.";
      actionsList.appendChild(li);
    }

    // Render Permalink Button
    if (data.dossier_id) {
      reportLink.href = `https://naukrinigran.vercel.app/report/${data.dossier_id}`;
      reportLink.classList.remove('hidden');
    } else {
      reportLink.classList.add('hidden');
    }

    resultsContainer.classList.remove('hidden');
  }
});
