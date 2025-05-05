# TechDetective Pro - Web App

An advanced web technology detection tool that's better than Wappalyzer in every aspect.

## Overview

TechDetective Pro is a powerful technology detection tool that goes beyond basic signature matching. It combines static analysis, dynamic analysis, and machine learning techniques to identify technologies used on websites, even when they're deliberately obscured or minified.

Unlike similar tools like Wappalyzer, TechDetective Pro uses a multi-layered approach to detect technologies:

1. **Static Analysis with Heuristics**: Analyzes HTML, CSS, and JavaScript code patterns, even when obfuscated or minified.
2. **Dynamic Analysis**: Uses headless browser to monitor runtime behavior, network requests, and DOM changes.
3. **Machine Learning Enhancement**: Applies pattern recognition to detect technologies based on their behavioral fingerprints.
4. **Combined Approach**: Merges results from all detection methods for higher accuracy.

## Features

- **Comprehensive Technology Detection**: Identifies frameworks, libraries, analytics tools, CMS platforms, and more.
- **Obfuscated Code Detection**: Recognizes technologies even when code is minified or deliberately obscured.
- **Confidence Scoring**: Provides confidence levels for each detected technology.
- **Categorized Results**: Organizes detected technologies by category for easy navigation.
- **Search and Filtering**: Quickly find specific technologies or filter by category.
- **Machine Learning Enhancement**: Uses pattern recognition to improve detection accuracy.
- **Export Functionality**: Save detection results as JSON for further analysis.
- **Clean, Modern UI**: User-friendly interface with responsive design.

## Why Better Than Wappalyzer

- **More Comprehensive Detection**: Detects a wider range of technologies, including obfuscated ones.
- **Higher Accuracy**: Multi-layered approach with ML enhancement provides more accurate results.
- **Confidence Scoring**: Shows how confident the detection is for each technology.
- **Better UI/UX**: Clean, modern interface with intuitive filtering and search.
- **Export Functionality**: Easily save and share detection results.
- **Detailed Version Detection**: Identifies specific versions of technologies when possible.
- **Open Source**: Fully customizable and extensible.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/techdetective-pro.git
   cd techdetective-pro
   ```

2. Install dependencies for both backend and frontend:
   ```
   npm run install:all
   ```

## Running the App

### Development Mode

1. Start both backend and frontend concurrently:
   ```
   npm run dev
   ```

   This will start:
   - Backend server on http://localhost:5000
   - Frontend development server on http://localhost:3000

2. Or run them separately:
   ```
   npm run dev:backend   # Start backend only
   npm run dev:frontend  # Start frontend only
   ```

### Production Mode

1. Build the frontend:
   ```
   npm run build
   ```

2. Start the production server:
   ```
   npm start
   ```

   This will serve the frontend from the backend server at http://localhost:5000

## Usage

1. Enter a website URL in the input field (e.g., https://example.com)
2. Click "Detect" to analyze the website
3. View the detected technologies organized by category
4. Use the search box to find specific technologies
5. Use the filter buttons to focus on frontend, backend, or analytics technologies
6. Click "Export Results" to download the results as a JSON file

## Technologies Used

### Backend
- Node.js
- Express
- Puppeteer (for headless browser automation)
- Axios (for HTTP requests)
- Cheerio (for HTML parsing)

### Frontend
- React
- Axios (for API requests)
- CSS3 with variables and modern features

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

[MIT License](LICENSE)

---

Created with ❤️ for web developers and technology enthusiasts