// scanner.js

import path from 'path';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import pLimit from 'p-limit';
import {
  writeResultsToCsv,
  writeErrorLogToCsv,
  getCsvFilePath
} from './csv-utils.js';
import UserAgent from 'user-agents';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const stealth = StealthPlugin();
puppeteer.use(stealth);

const SCRAPER_API_PROXY_PASS = '9c68321ea50eae9c33cfeb4aed9c1d10';

let browser;
async function launchBrowser(proxy = null) {
  if (browser) {
    try {
      await browser.close();
    } catch (_) {}
  }

  const args = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-web-security',
    '--disable-features=IsolateOrigins,site-per-process',
    '--ignore-certificate-errors',
    '--ignore-ssl-errors'
  ];

  if (proxy) {
    args.push(`--proxy-server=${proxy}`);
  }

  browser = await puppeteer.launch({
    headless: 'new',
    args,
    protocolTimeout: 120000
  });
}

export const getDomFeatures = async (page, url, userAgent) => {
  const safeEval = async (fn, fallback) => {
    try {
      return await page.evaluate(fn);
    } catch {
      return fallback;
    }
  };

  try {
    if (!page.isClosed()) {
      await page.setUserAgent(userAgent);
    }
  } catch (err) {
    console.warn(`⚠️ Failed to set User-Agent: ${err.message}`);
  }

  await page.setViewport({ width: 1366, height: 768 });
  await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US,en;q=0.9' });
  await page.setJavaScriptEnabled(true);

  await delay(500);
  // await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 120000 });
  } catch (_) {
    try {
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 120000 });
    } catch (e) {
      throw new Error(`Navigation failed (fallback too): ${e.message}`);
    }
}
 // trial changes

  const tagCounts = await safeEval(() => {
    const counts = {};
    const els = document.querySelectorAll('*');
    els.forEach(el => {
      const tag = el.tagName;
      counts[tag] = (counts[tag] || 0) + 1;
    });
    return {
      totalNodes: els.length,
      uniqueTags: Object.keys(counts).length
    };
  }, { totalNodes: -1, uniqueTags: -1 });

  const inlineJS = await safeEval(() => {
    let handlers = 0, hrefJS = 0;
    document.querySelectorAll('*').forEach(el => {
      handlers += [...el.attributes].filter(a => a.name.startsWith('on')).length;
      if (typeof el.href === 'string' && el.href.startsWith('javascript:')) hrefJS++;
    });
    return {
      inlineEventHandlers: handlers,
      javascriptHref: hrefJS
    };
  }, { inlineEventHandlers: -1, javascriptHref: -1 });

  const loginForms = await safeEval(() => {
    const forms = document.forms;
    let loginCount = 0;
    let externalFormActionBinary = 0;
    let externalFormActionNonBinary = 0;

    const suspiciousExtensions = ['.php', '.exe', '.bin', '.dll', '.js'];

    [...forms].forEach(form => {
      const hasPassword = [...form.elements].some(el => el.type === 'password');
      const rawAction = form.action || '';
      const actionStr = typeof rawAction === 'string' ? rawAction : String(rawAction);
      const isExternal = actionStr && !actionStr.includes(location.hostname);
      const isBinary = suspiciousExtensions.some(ext => actionStr.endsWith(ext));

      if (hasPassword) loginCount++;
      if (hasPassword && isExternal && isBinary) externalFormActionBinary++;
      if (hasPassword && isExternal && !isBinary) externalFormActionNonBinary++;
    });

    const passwordCount = document.querySelectorAll('input[type="password"]').length;

    return {
      loginFormCount: loginCount,
      passwordFieldCount: passwordCount,
      externalFormActionBinary,
      externalFormActionNonBinary
    };
  }, {
    loginFormCount: -1,
    passwordFieldCount: -1,
    externalFormActionBinary: -1,
    externalFormActionNonBinary: -1
  });

  const suspiciousKeywords = await safeEval(() => {
    const keywords = ['eval(', 'document.write', 'atob(', 'setTimeout(', 'setInterval(', 'iframe', 'unescape'];
    let suspicious = 0;
    document.querySelectorAll('script').forEach(s => {
      if (keywords.some(k => s.textContent.includes(k))) suspicious++;
    });
    return { suspiciousKeywords: suspicious };
  }, { suspiciousKeywords: -1 });

  const hiddenIframes = await safeEval(() => {
    let hidden = 0;
    document.querySelectorAll('iframe').forEach(iframe => {
      const style = window.getComputedStyle(iframe);
      if (style.display === 'none' || style.visibility === 'hidden') hidden++;
    });
    return { hiddenIframeCount: hidden };
  }, { hiddenIframeCount: -1 });

  const suspiciousScripts = await safeEval(() => {
    const suspiciousSrc = ['.php', 'eval', 'base64', 'unescape'];
    let suspicious = 0;
    document.querySelectorAll('script').forEach(script => {
      if (suspiciousSrc.some(word => (script.src || '').includes(word))) suspicious++;
    });
    return { suspiciousScriptTags: suspicious };
  }, { suspiciousScriptTags: -1 });

  const otherFeatures = await safeEval(() => {
    const metaTags = document.querySelectorAll('meta').length;
    const scripts = [...document.querySelectorAll('script')];
    const externalScripts = scripts.filter(s => s.src).length;
    const inlineScripts = scripts.length - externalScripts;
    const externalLinks = [...document.querySelectorAll('a')].filter(a => typeof a.href === 'string' && !a.href.includes(location.hostname)).length;
    const embeddedObjects = document.querySelectorAll('embed, object').length;
    const suspiciousInlineStyles = [...document.querySelectorAll('*')].filter(el => /display\s*:\s*none|visibility\s*:\s*hidden/i.test(el.getAttribute('style') || '')).length;
    const suspiciousLinkCount = [...document.querySelectorAll('a')].filter(a => typeof a.href === 'string' && /\.php|\.exe|base64/i.test(a.href)).length;

    return {
      metaTagCount: metaTags,
      externalScriptCount: externalScripts,
      inlineScriptCount: inlineScripts,
      externalLinkCount: externalLinks,
      embeddedObjectCount: embeddedObjects,
      suspiciousInlineStyleCount: suspiciousInlineStyles,
      suspiciousLinkCount,
      scriptCount: document.scripts.length,
      linkCount: document.links.length,
      iframeCount: document.querySelectorAll('iframe').length,
      formCount: document.forms.length
    };
  }, {
    metaTagCount: -1,
    externalScriptCount: -1,
    inlineScriptCount: -1,
    externalLinkCount: -1,
    embeddedObjectCount: -1,
    suspiciousInlineStyleCount: -1,
    suspiciousLinkCount: -1,
    scriptCount: -1,
    linkCount: -1,
    iframeCount: -1,
    formCount: -1
  });

  const frameNavigationFeatures = await safeEval(() => {
    const frames = Array.from(window.frames);
      let navigatedFrameCount = 0;
      let externalFrameCount = 0;
      let hasSuspiciousFrameUrl = false;

      const suspiciousIndicators = ['.php', '.exe', 'base64', 'eval'];

      for (let i = 0; i < window.frames.length; i++) {
        try {
          const frame = window.frames[i];
          const frameUrl = frame.location.href;

          if (frameUrl && frameUrl !== location.href) navigatedFrameCount++;
          if (frameUrl && !frameUrl.includes(location.hostname)) externalFrameCount++;
          if (frameUrl && suspiciousIndicators.some(ind => frameUrl.includes(ind))) {
            hasSuspiciousFrameUrl = true;
          }
        } catch (e) {
          // Cross-origin or detached frame — treat as external
          externalFrameCount++;
        }
      }
        return { navigatedFrameCount, 
          externalFrameCount, 
          hasSuspiciousFrameUrl: hasSuspiciousFrameUrl ? 1 : 0};
      }, {
          navigatedFrameCount: -1,
          externalFrameCount: -1,
          hasSuspiciousFrameUrl: -1,
        });


  return {
    ...tagCounts,
    ...inlineJS,
    ...loginForms,
    ...suspiciousKeywords,
    ...hiddenIframes,
    ...suspiciousScripts,
    ...otherFeatures,
    ...frameNavigationFeatures
  };
};


async function tryScan(page, url, sslBypass, userAgent) {
  const client = await page.target().createCDPSession();
  if (sslBypass && url.startsWith('https://')) {
    await client.send('Security.setIgnoreCertificateErrors', { ignore: true });
  }
  return await getDomFeatures(page, url, userAgent);
}

export const scanUrls = async (urls, concurrencyLimit = 10) => {
  const limit = pLimit(concurrencyLimit);
  const proxyLimit = pLimit(5);
  const results = {};
  const errorLog = [];

  await launchBrowser();

  async function scanWithRetry(originalUrl) {
    const baseUrl = originalUrl.replace('://www.', '://');
    const versions = [
      { url: originalUrl, sslBypass: false },
      { url: baseUrl, sslBypass: false },
      { url: originalUrl, sslBypass: true },
      { url: baseUrl, sslBypass: true }
    ];

    const proxyRetryErrors = [
      'net::ERR_BLOCKED_BY_CLIENT',
      'net::ERR_CONNECTION_REFUSED',
      'net::ERR_CONNECTION_TIMED_OUT',
      'ERR_SSL_VERSION_OR_CIPHER_MISMATCH',
      'net::ERR_SSL_PROTOCOL_ERROR',
      'net::ERR_SSL_UNRECOGNIZED_NAME_ALERT',
      'net::ERR_HTTP2_PROTOCOL_ERROR',
      'net::ERR_CONNECTION_RESET'
    ];

    let userAgent = new UserAgent().toString();
    let errorMsgs = [];
    let proxyNeeded = false;

    for (let { url, sslBypass } of versions) {
      let page;
      try {
        page = await browser.newPage();
        await delay(2000);
        await page.setRequestInterception(true);
        page.on('request', req => {
          const type = req.resourceType();
          if (["image", "stylesheet", "font"].includes(type)) req.abort();
          else req.continue();
        });

        const features = await tryScan(page, url, sslBypass, userAgent);
        await delay(1000 + Math.random() * 500);
        await page.close();

        return {
          features,
          finalUrl: url,
          sslBypassUsed: sslBypass ? 1 : 0,
          usedProxy: false,
          userAgent
        };

      } catch (err) {
        errorMsgs.push(`${sslBypass ? 'SSL Bypass' : 'Try'}: ${err.message}`);
        if (err.message.includes('Protocol error: Connection closed.')) {
          console.warn(`🔁 Relaunching browser due to closed connection at ${url}`);
          await delay(3000);
          await launchBrowser();
        }

        if (proxyRetryErrors.some(e => err.message.includes(e))) proxyNeeded = true;
      } finally {
        if (page) await page.close().catch(() => {});
      }
    }

    if (proxyNeeded) {
      console.warn(`🌐 Retrying ${originalUrl} using ScraperAPI URL proxy`);

      await proxyLimit(async () => {
        for (let { url } of versions) {
          let page;
          try {
            const scraperApiUrl = `http://api.scraperapi.com/?api_key=${SCRAPER_API_PROXY_PASS}&url=${encodeURIComponent(url)}`;

            page = await browser.newPage();
            await page.setRequestInterception(true);
            page.on('request', req => {
              const type = req.resourceType();
              if (["image", "stylesheet", "font"].includes(type)) req.abort();
              else req.continue();
            });

            const features = await tryScan(page, scraperApiUrl, false, userAgent);
            await delay(1000 + Math.random() * 500);
            await page.close();

            result = {
              features,
              finalUrl: url,
              sslBypassUsed: 0,
              usedProxy: true,
              userAgent
            };
          } catch (err) {
            errorMsgs.push(`ScraperAPI (fallback): ${err.message}`);
          } finally {
            if (page) await page.close().catch(() => {});
          }
        }
      });
    }

    throw new Error(errorMsgs.map(msg => `- ${msg}`).join('\n'));
  }

  const tasks = urls.map(({ url, label }) =>
    limit(async () => {
      try {
        const { features, finalUrl, sslBypassUsed, usedProxy, userAgent } = await scanWithRetry(url);
        results[url] = {
          ...features,
          sslBypassUsed,
          usedProxy: Number(usedProxy),
          finalUrlTried: finalUrl,
          label
        };
        console.log(`✅ Scanned: ${url}`);
      } catch (err) {
        console.error(`❌ Failed URL: ${url}`);
        console.error(`   ↳ Error: ${err.message}`);
        results[url] = {error: err.message, finalUrlTried: url,label};
        errorLog.push({url,error: err.message});
      }
    })
  );

  await Promise.all(tasks);

  try {
    if (browser) await browser.close();
  } catch (_) {}

  await writeResultsToCsv(getCsvFilePath(), results);
  return results;
};

