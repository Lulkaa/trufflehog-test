const fs = require('fs');
const path = 'trufflehog_results.json';


let raw = fs.readFileSync(path, 'utf8');

const lines = raw.trim().split('\n').filter(line => line.trim());
const vulnerabilities = [];

for (const line of lines) {
  try {
    const parsed = JSON.parse(line);
    vulnerabilities.push(parsed);
  } catch (e) {
    console.error('Error parsing line:', e.message);
  }
}

const hasIssues = vulnerabilities.length > 0;

const mdRow = (v) => {
  const detector = v.DetectorName || 'Unknown';
  const file = v.SourceMetadata?.Data?.Git?.file || 'N/A';
  const commit = v.SourceMetadata?.Data?.Git?.commit || 'N/A';
  const line = v.SourceMetadata?.Data?.Git?.line || 'N/A';
  const email = v.SourceMetadata?.Data?.Git?.email || 'N/A';
  const timestamp = v.SourceMetadata?.Data?.Git?.timestamp || 'N/A';
  const verified = v.Verified ? ' Verified' : 'Unverified';
  const raw = v.Raw ? `\`${v.Raw.substring(0, 30)}...\`` : 'N/A';
  const description = v.DetectorDescription || 'No description';
  
  return `
###  ${detector}
- **File**: \`${file}\` (line ${line})
- **Commit**: \`${commit.substring(0, 8)}\`
- **Author**: ${email}
- **Date**: ${timestamp}
- **Status**: ${verified}
- **Raw value**: ${raw}
- **Description**: ${description}
`;
};

const header = hasIssues
  ? `## ‼️WARNING‼️  TruffleHog found ${vulnerabilities.length} potential secret(s).`
  : `## TruffleHog: No vulnerabilities found`;

const body = [
  header,
  '',
  hasIssues ? '##Details of found secrets:\n' : '',
  hasIssues ? vulnerabilities.map(mdRow).join('\n---\n') : '✅ Scan completed successfully! No secrets or tokens detected.',
  '',
  
].join('\n');

fs.writeFileSync('pretty_comment.md', body);
console.log(`has_issues=${hasIssues}`);
fs.writeFileSync(process.env.GITHUB_OUTPUT || '.github_output', `has_issues=${hasIssues}\n`, { flag: 'a' });
