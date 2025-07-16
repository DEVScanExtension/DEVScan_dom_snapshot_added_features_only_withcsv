// csv-utils.js
import path from 'path';
import fs from 'fs/promises';
import fsSync from 'fs';
import csv from 'csv-parser';
import { createObjectCsvWriter } from 'csv-writer';

const outputsDir = path.join(process.cwd(), 'outputs');
const csvFilePath = path.join(outputsDir, 'dom-dataset.csv');

export function getCsvFilePath() {
  return csvFilePath;
}

export async function readUrlsFromCsv(filePath) {
  const csv = await import('csv-parser');
  return new Promise((resolve, reject) => {
    const urls = [];
    fsSync.createReadStream(filePath)
      .pipe(csv.default())
      .on('data', (row) => {
        const url = row.url || row.URL || Object.values(row)[0];
        const label = row.label || Object.values(row)[1] || '';
        if (url) urls.push({ url, label });  // ✅ push object with url and label
      })
      .on('end', () => resolve(urls))
      .on('error', reject);
  });
}


export async function writeResultsToCsv(filePath, results) {
  const dataArray = Object.entries(results)
  .filter(([_, features]) => !features.error)
  .map(([url, features]) => ({
    url,
    ...features,
  }));


  if (dataArray.length === 0) {
    dataArray.push({ url: 'N/A', status: 'No results found' });
  }

  await fs.mkdir(path.dirname(filePath), { recursive: true });

  const fileExists = fsSync.existsSync(filePath);

  // Collect all keys across all result rows to form headers
  const allKeys = new Set();
  dataArray.forEach(row => {
    Object.keys(row).forEach(k => allKeys.add(k));
  });

  const orderedKeys = ['url', 'label', ...[...allKeys].filter(k => k !== 'url' && k !== 'label')];
  const headers = orderedKeys.map(key => ({ id: key, title: key }));

  // Initialize CSV writer
  const csvWriter = createObjectCsvWriter({
    path: filePath,
    header: headers,
    append: fileExists, // append only if file exists
  });


  await csvWriter.writeRecords(dataArray);
}

export async function writeErrorLogToCsv(filePath, errors) {
  if (!Array.isArray(errors)) {
    console.warn('⚠️ writeErrorLogToCsv received invalid input:', errors);
    return;
  }
  
  const errorArray = errors.map(({ url, error }) => ({ url, error }));

  if (errorArray.length === 0) return;

  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });

  const csvWriter = createObjectCsvWriter({
    path: filePath,
    header: [
      { id: 'url', title: 'URL' },
      { id: 'error', title: 'Error Message' },
    ],
    append: true,
  });

  await csvWriter.writeRecords(errorArray);
}