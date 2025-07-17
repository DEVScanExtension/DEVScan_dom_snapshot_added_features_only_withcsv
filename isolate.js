const page = await browser.newPage();
const target = await browser.waitForTarget(t => t.type() === 'page' && t.url() === page.url(), { timeout: 5000 });
if (!target) throw new Error('No valid page target found');

// Optional: Delay to stabilize
await delay(500);

// Request blocking
await page.setRequestInterception(true);
page.on('request', req => {
  const type = req.resourceType();
  if (["image", "stylesheet", "font"].includes(type)) return req.abort();
  req.continue();
});

// Navigation debugging
page.on('framenavigated', frame => {
  console.warn(`⚠️ Frame navigated: ${frame.url()}`);
});

// Do your scan
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
