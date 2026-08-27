# Is This Safe?

A lightweight browser-based phishing and scam detector built with HTML, CSS, and vanilla JavaScript.

## Overview

This project analyzes suspicious text and optional links to identify common scam indicators such as:

- urgency pressure
- impersonation signals
- credential requests
- payment demands
- suspicious domains and shortened links
- social engineering language

It generates:

- a risk score from 0 to 100
- a verdict (SAFE, SUSPICIOUS, or DANGEROUS)
- a short explanation
- recommended actions
- recent scan history stored in localStorage

## Run locally

Open the project folder in a browser, or serve it locally with a simple static server:

```bash
cd is-this-safe
py -m http.server 8000
```

Then open http://localhost:8000

## Notes

- This is a client-side, pattern-based system intended for awareness and demo use.
- The architecture is designed so a real AI provider can be integrated later without changing the UI.
- For important decisions, always verify through an official and trusted channel.
