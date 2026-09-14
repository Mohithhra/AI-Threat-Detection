document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scan-email-btn');
  const resultsCard = document.getElementById('results-card');
  const statusText = document.getElementById('status-text');

  scanBtn.addEventListener('click', async () => {
    scanBtn.disabled = true;
    scanBtn.innerText = 'Scanning...';
    statusText.innerText = 'Extracting email text from webmail page...';

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      statusText.innerText = 'No active tab found.';
      scanBtn.disabled = false;
      scanBtn.innerText = '🛡️ Scan Active Email Body';
      return;
    }

    chrome.tabs.sendMessage(tab.id, { action: "extract_email" }, async (response) => {
      if (!response || !response.content) {
        statusText.innerText = 'Could not extract email content from current tab. Ensure Gmail or Outlook email is open.';
        scanBtn.disabled = false;
        scanBtn.innerText = '🛡️ Scan Active Email Body';
        return;
      }

      statusText.innerText = 'Sending to SentinelEML Threat Engine...';

      try {
        const formData = new FormData();
        formData.append("raw_content", response.content);

        const res = await fetch("http://localhost:8000/api/analyze", {
          method: "POST",
          body: formData
        });

        if (!res.ok) throw new Error("API analysis failed");

        const data = await res.json();
        renderResults(data);
        statusText.innerText = 'Analysis complete!';
      } catch (err) {
        statusText.innerText = 'Error: ' + err.message;
      } finally {
        scanBtn.disabled = false;
        scanBtn.innerText = '🛡️ Scan Active Email Body';
      }
    });
  });

  function renderResults(data) {
    resultsCard.style.display = 'block';
    const risk = data.risk_assessment || {};
    const aiIntent = data.ai_intent_analysis || {};
    const auth = data.parsed_headers?.authentication || {};

    const badge = document.getElementById('score-badge');
    badge.innerText = `${risk.score}/100 (${risk.threat_level})`;
    badge.className = `score-badge ${risk.threat_level === 'MALICIOUS' ? 'score-malicious' : 'score-clean'}`;

    document.getElementById('tactic-text').innerText = aiIntent.primary_tactic || 'General Phishing';
    document.getElementById('auth-text').innerText = `SPF:${auth.spf_status || 'none'} | DKIM:${auth.dkim_status || 'none'}`;
    document.getElementById('summary-text').innerText = risk.summary || aiIntent.ai_summary || '';
  }
});
