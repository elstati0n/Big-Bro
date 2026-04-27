# Privacy Policy - ElHunter

**Last updated: April 27, 2026**

ElHunter ("the Extension") is a Google Chrome extension that provides real-time threat intelligence and phishing detection. This Privacy Policy explains what user data the Extension handles, how it is handled, where it is stored, how long it is retained, and when it is shared.

---

## 1. Summary

- The ElHunter developer does not operate a backend that receives your browsing data, email content, API keys, or scan results.
- The Extension does handle certain data in your browser to provide its security features.
- The Extension sends limited data directly from your browser to third-party services that are necessary for scanning, geolocation, notifications, or optional AI analysis.
- The Extension does not sell user data, does not use user data for advertising, and does not build advertising profiles.

---

## 2. User Data the Extension Handles

Depending on which features you use, the Extension may handle the following categories of user data:

- **Visited URLs, domains, and IP addresses** of pages you open in the browser
- **Resolved IP addresses and network metadata** such as country, ISP/organization, and Cloudflare status
- **Links extracted from supported webmail pages** for phishing checks
- **Full email body text** only when you explicitly start AI analysis
- **User-provided configuration data** such as API keys, notification settings, Telegram settings, AI provider selection, model selection, and country rules
- **Threat cache and allow/block state** used to avoid repeated lookups and preserve user actions

Some of this data, such as visited URLs or email content, may contain personal or sensitive information depending on what you visit or choose to analyze.

---

## 3. Data Stored Locally

The Extension stores data in Chrome extension storage:

### `chrome.storage.sync`

This storage may be synchronized by Google across devices signed in to the same Chrome profile if Chrome Sync is enabled.

The Extension stores the following in `chrome.storage.sync`:

- ZeroScan API key
- Telegram bot token and Telegram chat ID
- AI provider API key
- AI provider, model, and optional custom endpoint settings
- Notification settings
- Country rules
- Email phishing feature toggles

### `chrome.storage.local`

This storage remains on the local device unless Chrome itself migrates extension data.

The Extension stores the following in `chrome.storage.local`:

- Threat scan cache for domains, IPs, and URLs
- Resolved IP, country, ISP/organization, category, verdict, and related metadata
- Temporary or persistent unblock state
- Popup UI state such as the last opened tab

The threat cache is retained for up to **14 days** unless removed earlier by the user or replaced by newer data.

The Extension does **not** store full email body text in `chrome.storage.sync` or `chrome.storage.local`.

---

## 4. Data Sent to Third-Party Services

To provide its features, the Extension sends data directly from your browser to third-party services. The ElHunter developer does not proxy these requests through developer-operated servers.

| Service | Data sent | Purpose |
|---|---|---|
| [ZeroScan](https://zeroscan.az) | URL, domain, or IP address being checked | Threat verdict and category lookup |
| [networkcalc.com](https://networkcalc.com) | Domain or hostname being checked | DNS resolution from domain to IP |
| [ipinfo.io](https://ipinfo.io/privacy) | Resolved IP address | Country, ISP/organization, and network metadata |
| [Telegram Bot API](https://telegram.org/privacy) | Alert content such as domain/URL, verdict, country, resolved IP, and Cloudflare status | Optional Telegram threat notifications |
| AI providers selected by the user (such as OpenAI, Anthropic, Google Gemini, Mistral, Groq, OpenRouter, Ollama, LM Studio, or a custom OpenAI-compatible endpoint) | Email body text and analysis prompt, only when the user explicitly requests AI analysis | Optional phishing probability analysis |

Third-party services process data according to their own privacy policies and retention practices. You should review those policies before using the related features.

---

## 5. Email Phishing Detection

The Extension injects a content script only on supported webmail services:

- `mail.google.com`
- `outlook.live.com`
- `outlook.office.com`
- `outlook.office365.com`
- `mail.yahoo.com`
- `mail.proton.me`
- `protonmail.com`

### Automatic link scanning

When link scanning is enabled, the Extension extracts URLs from the currently opened email and checks those URLs or their hosts against ZeroScan. This feature is used to detect malicious or suspicious links inside email messages.

The Extension does **not** send the full email subject, sender name, recipient list, or full email body to ZeroScan for automatic link scanning. Only extracted links, URLs, domains, or IPs needed for the check are sent.

### Optional AI analysis

When you explicitly click the AI analysis button, the Extension sends the full email body text to your configured AI provider for phishing analysis. This does not happen automatically.

Because email bodies may contain personal or sensitive information, you should enable AI analysis only if you are comfortable sending that content to the selected AI provider under that provider's own privacy policy.

---

## 6. How User Data Is Shared

User data is shared only in the following cases:

- With **Google**, if Chrome Sync is enabled and you use settings stored in `chrome.storage.sync`
- With **ZeroScan**, when the Extension checks a URL, domain, or IP for threat intelligence
- With **networkcalc.com** and **ipinfo.io**, when the Extension resolves and enriches network information
- With **Telegram**, if you enable Telegram alerts
- With an **AI provider chosen by you**, if you explicitly request email AI analysis

The Extension does **not** share user data with the ElHunter developer, advertisers, data brokers, or unrelated third parties.

---

## 7. Data Retention and User Controls

- Threat cache entries are kept for up to **14 days**
- Settings and API keys remain stored until you remove them, disable Chrome Sync, or uninstall the Extension
- Full email body text used for AI analysis is not stored in Chrome extension storage by ElHunter
- You can clear cached scan results from the Extension UI
- You can remove API keys and disable optional features such as Telegram alerts or AI analysis at any time
- Uninstalling the Extension removes its local extension data from the browser environment

---

## 8. Security

The Extension relies on Chrome extension storage and HTTPS requests for data transmission where supported by the selected provider. API keys are stored in Chrome extension storage and sent only to the service they are meant for.

If you use a local or custom AI endpoint, data handling and transport security depend on that endpoint's configuration.

---

## 9. Children's Privacy

The Extension is not directed to children under 13 and is not intended for use by children.

---

## 10. Changes to This Policy

If this Privacy Policy changes, the updated version will be published with a revised "Last updated" date.

---

## 11. Contact

For questions about this Privacy Policy or ElHunter's data handling, open an issue at:

[https://github.com/elstati0n/ELHunter](https://github.com/elstati0n/ELHunter)
