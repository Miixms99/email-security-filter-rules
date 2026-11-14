'use strict';
// Re-runs the analyzer offline on every corpus sample and fails if detection
// changes from the recorded matchedRuleIds (regression guard). Prints a
// per-category detection summary.
const assert = require('node:assert/strict');
const { readSamples, evaluateSample } = require('../scripts/corpus.cjs');
const byCategory = {};
for (const { sample } of readSamples()) {
  const { matchedRuleIds } = evaluateSample(sample);
  const row = byCategory[sample.category] ||= { total: 0, detected: 0 };
  row.total++; if (matchedRuleIds.length) row.detected++;
  for (const id of sample.matchedRuleIds) assert.ok(matchedRuleIds.includes(id), `${sample.id}: lost detection by ${id}`);
  const added = matchedRuleIds.filter(id => !sample.matchedRuleIds.includes(id));
  if (added.length) console.log(`${sample.id}: newly matched ${added.join(', ')} (update matchedRuleIds)`);
  if (sample.category === 'ad') assert.ok(!matchedRuleIds.some(id => id.startsWith('campaign.')), `${sample.id}: legitimate ad matched a campaign rule`);
}
console.log('Corpus detection: ' + Object.entries(byCategory).map(([c, r]) => `${c} ${r.detected}/${r.total}`).join(', ') + '.');
