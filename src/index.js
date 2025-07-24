// src/index.js (standard Create React App setup)
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App'; // This imports your App component
import reportWebVitals from './reportWebVitals'; // If you have this

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// If you have reportWebVitals
// reportWebVitals();
