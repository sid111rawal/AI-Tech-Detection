import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilter, setActiveFilter] = useState('all');

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!url) {
      setError('Please enter a URL');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      
      const response = await axios.post('/api/detect', { url });
      
      if (response.data.success) {
        setResults(response.data);
      } else {
        setError(response.data.message || 'Failed to detect technologies');
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    if (!results) return;
    
    const exportData = JSON.stringify(results, null, 2);
    const blob = new Blob([exportData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `techdetective-${new Date().getTime()}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
  };

  const filterByCategory = (category) => {
    setActiveFilter(category);
  };

  const filterBySearch = (term) => {
    setSearchTerm(term);
  };

  const getFilteredTechnologies = () => {
    if (!results) return {};
    
    const { technologies } = results;
    const filtered = {};
    
    // Filter by category
    if (activeFilter === 'all') {
      Object.keys(technologies).forEach(category => {
        filtered[category] = technologies[category];
      });
    } else {
      const categoryGroups = {
        frontend: ['javascript_frameworks', 'javascript_libraries', 'ui_frameworks', 'css_frameworks'],
        backend: ['web_frameworks', 'server', 'programming_languages', 'databases', 'reverse_proxies'],
        analytics: ['analytics', 'marketing']
      };
      
      (categoryGroups[activeFilter] || []).forEach(category => {
        if (technologies[category]) {
          filtered[category] = technologies[category];
        }
      });
    }
    
    // Filter by search term
    if (searchTerm) {
      Object.keys(filtered).forEach(category => {
        filtered[category] = filtered[category].filter(tech => 
          tech.name.toLowerCase().includes(searchTerm.toLowerCase())
        );
      });
      
      // Remove empty categories
      Object.keys(filtered).forEach(category => {
        if (filtered[category].length === 0) {
          delete filtered[category];
        }
      });
    }
    
    return filtered;
  };

  const getCategoryDisplayName = (category) => {
    const displayNames = {
      javascript_frameworks: 'JavaScript Frameworks',
      javascript_libraries: 'JavaScript Libraries',
      ui_frameworks: 'UI Frameworks',
      css_frameworks: 'CSS Frameworks',
      web_frameworks: 'Web Frameworks',
      analytics: 'Analytics',
      payment_processors: 'Payment Processors',
      cms: 'Content Management',
      ecommerce: 'E-Commerce',
      security: 'Security',
      server: 'Server',
      reverse_proxies: 'Reverse Proxies',
      programming_languages: 'Programming Languages',
      databases: 'Databases',
      caching: 'Caching',
      cdn: 'CDN',
      marketing: 'Marketing',
      cookie_compliance: 'Cookie Compliance',
      development: 'Development Tools',
      miscellaneous: 'Miscellaneous'
    };
    
    return displayNames[category] || category.replace(/_/g, ' ');
  };

  const filteredTechnologies = getFilteredTechnologies();

  return (
    <div className="app">
      <header className="header">
        <div className="logo-container">
          <h1>TechDetective Pro</h1>
          <p>Advanced Website Technology Detector</p>
        </div>
      </header>
      
      <main className="main">
        <form className="url-form" onSubmit={handleSubmit}>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter website URL (e.g. https://example.com)"
            className="url-input"
            required
          />
          <button type="submit" className="detect-button" disabled={loading}>
            {loading ? 'Analyzing...' : 'Detect'}
          </button>
        </form>
        
        {error && (
          <div className="error-message">
            <p>{error}</p>
          </div>
        )}
        
        {loading && (
          <div className="loading">
            <div className="spinner"></div>
            <p>Analyzing website technologies...</p>
            <p className="loading-note">This may take up to 15 seconds</p>
          </div>
        )}
        
        {results && !loading && (
          <div className="results">
            <div className="results-header">
              <div className="url-info">
                <span className="url-label">URL:</span>
                <span className="url-value">{results.url}</span>
              </div>
              
              <div className="filters">
                <div className="search-container">
                  <input
                    type="text"
                    placeholder="Search technologies..."
                    value={searchTerm}
                    onChange={(e) => filterBySearch(e.target.value)}
                    className="search-input"
                  />
                </div>
                
                <div className="filter-buttons">
                  <button
                    className={`filter-btn ${activeFilter === 'all' ? 'active' : ''}`}
                    onClick={() => filterByCategory('all')}
                  >
                    All
                  </button>
                  <button
                    className={`filter-btn ${activeFilter === 'frontend' ? 'active' : ''}`}
                    onClick={() => filterByCategory('frontend')}
                  >
                    Frontend
                  </button>
                  <button
                    className={`filter-btn ${activeFilter === 'backend' ? 'active' : ''}`}
                    onClick={() => filterByCategory('backend')}
                  >
                    Backend
                  </button>
                  <button
                    className={`filter-btn ${activeFilter === 'analytics' ? 'active' : ''}`}
                    onClick={() => filterByCategory('analytics')}
                  >
                    Analytics
                  </button>
                </div>
              </div>
            </div>
            
            <div className="tech-categories">
              {Object.keys(filteredTechnologies).length > 0 ? (
                Object.keys(filteredTechnologies).map(category => (
                  <div key={category} className="tech-category">
                    <div className="category-header">
                      <h2 className="category-name">{getCategoryDisplayName(category)}</h2>
                      <span className="tech-count">{filteredTechnologies[category].length}</span>
                    </div>
                    
                    <div className="tech-list">
                      {filteredTechnologies[category].map((tech, index) => (
                        <div key={`${tech.name}-${index}`} className="tech-item">
                          <div className="tech-info">
                            <div className="tech-name-container">
                              <span className="tech-name">{tech.name}</span>
                              {tech.version && (
                                <span className="tech-version">{tech.version}</span>
                              )}
                            </div>
                            
                            <div className="tech-meta">
                              <span className="tech-confidence">
                                {Math.round(tech.confidence * 100)}%
                              </span>
                              
                              {tech.detectedBy === 'ml' && (
                                <span className="tech-ml-badge" title="Detected with Machine Learning">
                                  ML
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                <div className="no-results">
                  <p>No technologies found matching your criteria.</p>
                </div>
              )}
            </div>
            
            <div className="ml-badge">
              <span>Enhanced with Machine Learning</span>
            </div>
            
            <div className="export-container">
              <button className="export-button" onClick={handleExport}>
                Export Results
              </button>
            </div>
          </div>
        )}
      </main>
      
      <footer className="footer">
        <div className="footer-content">
          <span>TechDetective Pro v1.0.0</span>
          <span>Better than Wappalyzer in every aspect</span>
        </div>
      </footer>
    </div>
  );
}

export default App;