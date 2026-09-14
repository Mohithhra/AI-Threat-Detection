// Content Script for Gmail & Outlook Webmail Scraping
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_email") {
    let emailText = "";

    // 1. Try Gmail DOM elements
    const gmailSubject = document.querySelector('h2.hP')?.innerText || "";
    const gmailBody = document.querySelector('div.a3s.aiL')?.innerText || "";
    const gmailSender = document.querySelector('span.gD')?.getAttribute('email') || "";

    if (gmailBody) {
      emailText = `From: ${gmailSender}\nSubject: ${gmailSubject}\n\n${gmailBody}`;
    } else {
      // 2. Try Outlook Webmail DOM elements
      const outlookSubject = document.querySelector('div[role="heading"][title]')?.innerText || "";
      const outlookBody = document.querySelector('div[aria-label="Email message body"]')?.innerText || "";
      if (outlookBody) {
        emailText = `Subject: ${outlookSubject}\n\n${outlookBody}`;
      } else {
        // Fallback: full document body text
        emailText = document.body.innerText.substring(0, 3000);
      }
    }

    sendResponse({ content: emailText });
  }
  return true;
});
