const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

export class VirusTotalAPI {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.headers = {
      'x-apikey': apiKey,
      'Content-Type': 'application/json'
    };
  }

  // Scan URL
  async scanUrl(url) {
    const response = await fetch(`${VT_BASE_URL}/urls`, {
      method: 'POST',
      headers: { 'x-apikey': this.apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(url)}`
    });
    return await response.json();
  }

  // Get URL analysis
  async getUrlAnalysis(id) {
    const response = await fetch(`${VT_BASE_URL}/analyses/${id}`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Get URL report
  async getUrlReport(url) {
    const urlId = btoa(url).replace(/=/g, '');
    const response = await fetch(`${VT_BASE_URL}/urls/${urlId}`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Scan file
  async scanFile(fileBuffer, filename) {
    const formData = new FormData();
    formData.append('file', new Blob([fileBuffer]), filename);
    
    const response = await fetch(`${VT_BASE_URL}/files`, {
      method: 'POST',
      headers: { 'x-apikey': this.apiKey },
      body: formData
    });
    return await response.json();
  }

  // Get file report
  async getFileReport(hash) {
    const response = await fetch(`${VT_BASE_URL}/files/${hash}`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Get file analysis
  async getFileAnalysis(id) {
    const response = await fetch(`${VT_BASE_URL}/analyses/${id}`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Search
  async search(query) {
    const response = await fetch(`${VT_BASE_URL}/search?query=${encodeURIComponent(query)}`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Get IP address report
  async getIpReport(ip) {
    const response = await fetch(`${VT_BASE_URL}/ip_addresses/${ip}`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Get domain report
  async getDomainReport(domain) {
    const response = await fetch(`${VT_BASE_URL}/domains/${domain}`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Get comments
  async getComments(id, type = 'files') {
    const response = await fetch(`${VT_BASE_URL}/${type}/${id}/comments`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Add comment
  async addComment(id, comment, type = 'files') {
    const response = await fetch(`${VT_BASE_URL}/${type}/${id}/comments`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify({ data: { type: 'comment', attributes: { text: comment } } })
    });
    return await response.json();
  }

  // Get votes
  async getVotes(id, type = 'files') {
    const response = await fetch(`${VT_BASE_URL}/${type}/${id}/votes`, {
      headers: this.headers
    });
    return await response.json();
  }

  // Add vote
  async addVote(id, verdict, type = 'files') {
    const response = await fetch(`${VT_BASE_URL}/${type}/${id}/votes`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify({ data: { type: 'vote', attributes: { verdict } } })
    });
    return await response.json();
  }
}
