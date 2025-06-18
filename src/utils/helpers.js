export function formatFileReport(data) {
  const { attributes } = data;
  return `
<b>File Report:</b>
<b>File Name:</b> ${attributes.file_name}
<b>MD5:</b> ${attributes.md5}
<b>SHA1:</b> ${attributes.sha1}
<b>SHA256:</b> ${attributes.sha256}
<b>Size:</b> ${attributes.size} bytes
<b>Last Analysis Stats:</b>
- Malicious: ${attributes.last_analysis_stats.malicious}
- Undetected: ${attributes.last_analysis_stats.undetected}
- Suspicious: ${attributes.last_analysis_stats.suspicious}
<b>Last Analysis Date:</b> ${new Date(attributes.last_analysis_date * 1000).toLocaleString()}
`;
}

export function formatUrlReport(data) {
  const { attributes } = data;
  return `
<b>URL Report:</b>
<b>URL:</b> ${attributes.url}
<b>Last Analysis Stats:</b>
- Malicious: ${attributes.last_analysis_stats.malicious}
- Undetected: ${attributes.last_analysis_stats.undetected}
- Suspicious: ${attributes.last_analysis_stats.suspicious}
<b>Last Analysis Date:</b> ${new Date(attributes.last_analysis_date * 1000).toLocaleString()}
`;
}

export function formatIpReport(data) {
  const { attributes } = data;
  return `
<b>IP Report:</b>
<b>IP:</b> ${attributes.ip_address}
<b>Last Analysis Date:</b> ${new Date(attributes.last_analysis_date * 1000).toLocaleString()}
<b>Last Analysis Stats:</b>
- Malicious: ${attributes.last_analysis_stats.malicious}
- Undetected: ${attributes.last_analysis_stats.undetected}
`;
}

export function formatDomainReport(data) {
  const { attributes } = data;
  return `
<b>Domain Report:</b>
<b>Domain:</b> ${attributes.domain}
<b>Last Analysis Date:</b> ${new Date(attributes.last_analysis_date * 1000).toLocaleString()}
<b>Last Analysis Stats:</b>
- Malicious: ${attributes.last_analysis_stats.malicious}
- Undetected: ${attributes.last_analysis_stats.undetected}
`;
}
