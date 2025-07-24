// src/EInvoiceAuth.js
import React, { useState, useCallback } from 'react';
import {
  Container,
  TextField,
  Button,
  Box,
  Typography,
  Paper,
  Divider,
  Checkbox,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import JSEncrypt from 'jsencrypt'; // For RSA encryption
import { Buffer } from 'buffer'; // Node.js Buffer polyfill for browser environments
import CryptoJS from 'crypto-js'; // For AES decryption

// Polyfill Buffer if not globally available
if (typeof window !== 'undefined' && !window.Buffer) {
  window.Buffer = Buffer;
}

const EInvoiceAuth = () => {
  // State for input fields
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [gstin, setGstin] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [eInvoicePublicKey, setEInvoicePublicKey] = useState('');
  const [forceRefreshAccessToken, setForceRefreshAccessToken] = useState(false);

  // State for generated/intermediate values
  const [appKey, setAppKey] = useState('');
  const [rawPayloadJson, setRawPayloadJson] = useState('');
  const [base64EncodedPayload, setBase64EncodedPayload] = useState('');
  const [encryptedPayload, setEncryptedPayload] = useState(''); // This will be the 'Data' sent
  const [requestHeaders, setRequestHeaders] = useState('');

  // State for API response
  const [apiResponse, setApiResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Decrypted Session Encryption Key
  const [decryptedSek, setDecryptedSek] = useState('');


  // --- Step 1 & 2: Generate AppKey ---
  const generateAppKey = useCallback(() => {
    try {
      // Generate a random 32-byte array (using browser's crypto for security)
      const randomBytes = new Uint8Array(32);
      window.crypto.getRandomValues(randomBytes);

      // Base64 encode it
      const base64AppKey = Buffer.from(randomBytes).toString('base64');
      setAppKey(base64AppKey);
      setError(null);
    } catch (err) {
      setError(`Error generating AppKey: ${err.message}`);
      console.error(err);
    }
  }, []);

  // --- Step 3 & 4: Construct and Base64 Encode Payload ---
  const constructAndEncodePayload = useCallback(() => {
    if (!username || !password || !appKey) {
      setError('Username, Password, and AppKey are required to construct payload.');
      return;
    }
    try {
      const payloadData = {
        Username: username,
        Password: password,
        Appkey: appKey,
        ForceRefreshAccessToken: forceRefreshAccessToken,
      };
      const jsonStr = JSON.stringify(payloadData, null, 2);
      setRawPayloadJson(jsonStr);

      const base64Encoded = Buffer.from(jsonStr).toString('base64');
      setBase64EncodedPayload(base64Encoded);
      setError(null);
    } catch (err) {
      setError(`Error constructing/encoding payload: ${err.message}`);
      console.error(err);
    }
  }, [username, password, appKey, forceRefreshAccessToken]);

  // --- Step 5: Encrypt Payload ---
  const encryptPayload = useCallback(() => {
    // --- START DEBUG LOGS FOR ENCRYPT PAYLOAD ---
    console.log("--- Starting encryptPayload function ---");
    console.log("eInvoicePublicKey (input):", eInvoicePublicKey);
    console.log("base64EncodedPayload (input):", base64EncodedPayload);
    // --- END DEBUG LOGS ---

    if (!base64EncodedPayload || !eInvoicePublicKey) {
      setError('Base64 Encoded Payload and Public Key are required for encryption.');
      console.error("Encryption prerequisites missing: base64EncodedPayload or eInvoicePublicKey is empty.");
      return;
    }
    try {
      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(eInvoicePublicKey);

      // Important: js-encrypt uses PKCS#1 v1.5 padding by default.
      // If the E-Invoice system requires OAEP with SHA256, js-encrypt might not directly support it for RSA encryption.
      // Always consult the E-Invoice API documentation for exact encryption requirements.
      // If it's OAEP, you'll need a different library or a backend service.
      const encrypted = encrypt.encrypt(base64EncodedPayload);

      // --- START DEBUG LOGS FOR ENCRYPT PAYLOAD RESULT ---
      console.log("Result of JSEncrypt.encrypt():", encrypted);
      if (encrypted && typeof encrypted === 'string') {
        console.log("Encrypted payload length:", encrypted.length);
      } else {
        console.log("Encrypted payload is not a valid string.");
      }
      // --- END DEBUG LOGS ---

      if (!encrypted) {
        throw new Error("Encryption failed. Check public key format and payload size (too large for RSA).");
      }
      setEncryptedPayload(encrypted);
      setError(null);
    } catch (err) {
      setError(`Error encrypting payload: ${err.message}. Ensure public key is valid and in PEM format.`);
      console.error("Encryption Error Details:", err);
    }
    console.log("--- Finished encryptPayload function ---");
  }, [base64EncodedPayload, eInvoicePublicKey]);

  // --- Step 6: Construct Request Headers ---
  const constructHeaders = useCallback(() => {
    if (!clientId || !clientSecret || !gstin) {
      setError('Client ID, Client Secret, and GSTIN are required for headers.');
      return;
    }
    const headers = {
      'client_id': clientId,
      'client_secret': clientSecret,
      'Gstin': gstin,
      'Content-Type': 'application/json',
    };
    setRequestHeaders(JSON.stringify(headers, null, 2));
    setError(null);
  }, [clientId, clientSecret, gstin]);

  // --- AES Decryption for SEK (Session Encryption Key) ---
  const decryptSek = useCallback((encryptedSek) => {
    if (!appKey) {
      setError('AppKey is required to decrypt SEK.');
      return '';
    }
    if (!encryptedSek) {
      return '';
    }

    try {
      // The image states AES 256(AES/ECB/PKCS7Padding).
      // CryptoJS AES uses PKCS7 padding by default if not specified.
      // ECB mode means no IV is typically used, but it's generally less secure for large data.
      // Ensure the AppKey is properly used as a key. It's a Base64 string, so we'll use it directly.
      // Convert the Base64 AppKey to a WordArray as required by CryptoJS
      const keyWordArray = CryptoJS.enc.Base64.parse(appKey);

      // Decrypt the encrypted SEK (which is also Base64 encoded)
      const decrypted = CryptoJS.AES.decrypt(encryptedSek, keyWordArray, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7 // Explicitly set PKCS7 padding
      });

      // Convert the decrypted WordArray to a UTF-8 string
      const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);

      if (!decryptedString) {
          throw new Error("Decryption resulted in empty string. Check AppKey and SEK.");
      }

      setDecryptedSek(decryptedString);
      return decryptedString;

    } catch (err) {
      setError(`Error decrypting SEK: ${err.message}. Check AppKey and encrypted SEK format.`);
      console.error("SEK Decryption Error:", err);
      setDecryptedSek('Decryption Failed!');
      return '';
    }
  }, [appKey]);


  // --- Step 7 & 8: Make API Call ---
  const sendAuthenticationRequest = useCallback(async () => {
    // --- START DEBUG LOGS FOR SEND AUTH REQUEST ---
    console.log("--- Starting sendAuthenticationRequest function ---");
    console.log("Current encryptedPayload state:", encryptedPayload);
    // --- END DEBUG LOGS ---

    if (!encryptedPayload || !clientId || !clientSecret || !gstin) {
      setError('All prerequisite steps (AppKey, Payload, Encryption, Headers) must be completed.');
      console.error("Missing prerequisites for sending request:", { encryptedPayload, clientId, clientSecret, gstin });
      return;
    }

    setLoading(true);
    setError(null);
    setApiResponse(null);
    setDecryptedSek(''); // Clear previous SEK

    // IMPORTANT: Use the relative path for proxy to work in development
    const authUrl = "/eivital//v1.04/auth";

    const requestBody = {
      Data: encryptedPayload,
    };

    // --- START DEBUG LOGS FOR REQUEST BODY ---
    console.log("Request Body being sent:", JSON.stringify(requestBody, null, 2));
    // --- END DEBUG LOGS ---

    try {
      const headers = {
        'client_id': clientId,
        'client_secret': clientSecret,
        'Gstin': gstin,
        'Content-Type': 'application/json',
      };

      // --- START DEBUG LOGS FOR REQUEST HEADERS ---
      console.log("Request Headers being sent:", headers);
      console.log("Target URL:", authUrl);
      // --- END DEBUG LOGS ---

      const response = await fetch(authUrl, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(requestBody),
      });

      // --- START DEBUG LOGS FOR RAW RESPONSE ---
      console.log("Raw response object:", response);
      // --- END DEBUG LOGS ---

      const data = await response.json();

      // --- START DEBUG LOGS FOR PARSED RESPONSE ---
      console.log("Parsed API response data:", data);
      // --- END DEBUG LOGS ---

      if (!response.ok) {
        // If response.ok is false, it's an HTTP error (e.g., 4xx, 5xx)
        // The API returns 200 OK even for logical errors, so this might not catch "Status: 0"
        throw new Error(data.ErrorDetails?.[0]?.ErrorMessage || `HTTP error! Status: ${response.status}`);
      }

      setApiResponse(data);

      // If authentication is successful and SEK is returned, decrypt it
      if (data.Status === "1" && data.Sek) {
        decryptSek(data.Sek);
      } else if (data.Status === "0") {
          // Explicitly set error for API's logical error
          setError(data.ErrorDetails?.[0]?.ErrorMessage || "Authentication failed with Status: 0");
      }

    } catch (err) {
      setError(`API Request Failed: ${err.message}`);
      console.error("API Request Error:", err);
    } finally {
      setLoading(false);
      console.log("--- Finished sendAuthenticationRequest function ---");
    }
  }, [encryptedPayload, clientId, clientSecret, gstin, decryptSek]);


  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        E-Invoice Authentication Flow
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Input Parameters */}
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h5" gutterBottom>
          1. Input Parameters
        </Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 2 }}>
          <TextField
            label="Client ID"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            fullWidth
          />
          <TextField
            label="Client Secret"
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            fullWidth
          />
          <TextField
            label="GSTIN"
            value={gstin}
            onChange={(e) => setGstin(e.target.value)}
            fullWidth
          />
          <TextField
            label="Username (Tax Payer)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            fullWidth
          />
          <TextField
            label="Password (Tax Payer)"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            fullWidth
          />
          <TextField
            label="E-Invoice Public Key (PEM)"
            multiline
            rows={6}
            value={eInvoicePublicKey}
            onChange={(e) => setEInvoicePublicKey(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----"
            fullWidth
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={forceRefreshAccessToken}
                onChange={(e) => setForceRefreshAccessToken(e.target.checked)}
              />
            }
            label="Force Refresh Access Token (10 mins before expiry)"
          />
        </Box>
      </Paper>

      {/* Step-by-Step Accordions */}

      {/* Step 2: Generate AppKey */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">2. Generate Appkey</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={generateAppKey} sx={{ mb: 2 }}>
            Generate Random Appkey
          </Button>
          {appKey && (
            <Box sx={{ backgroundColor: '#f0f0f0', p: 2, borderRadius: 1, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Generated Appkey (Base64 Encoded):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'green' }}>{appKey}</Typography>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Step 3 & 4: Construct and Base64 Encode Payload */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">3. Construct & Base64 Encode Request Payload</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={constructAndEncodePayload} sx={{ mb: 2 }}>
            Construct and Encode Payload
          </Button>
          {rawPayloadJson && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1">Raw Payload JSON:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                {rawPayloadJson}
              </Paper>
            </Box>
          )}
          {base64EncodedPayload && (
            <Box>
              <Typography variant="subtitle1">Base64 Encoded Payload:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                {base64EncodedPayload}
              </Paper>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Step 5: Encrypt Payload */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">4. Encrypt Base64 Encoded Payload</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={encryptPayload} sx={{ mb: 2 }}>
            Encrypt Payload with Public Key
          </Button>
          {encryptedPayload && (
            <Box sx={{ backgroundColor: '#f0f0f0', p: 2, borderRadius: 1, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Encrypted Payload (Ready for 'Data' field):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'blue' }}>{encryptedPayload}</Typography>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Step 6: Construct Request Headers */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">5. Construct Request Headers</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={constructHeaders} sx={{ mb: 2 }}>
            Construct Headers
          </Button>
          {requestHeaders && (
            <Box sx={{ backgroundColor: '#f0f0f0', p: 2, borderRadius: 1 }}>
              <Typography variant="subtitle1">Request Headers:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                {requestHeaders}
              </Paper>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Step 7 & 8: Make API Call */}
      <Paper elevation={3} sx={{ p: 3, mt: 3 }}>
        <Typography variant="h5" gutterBottom>
          6. Send Authentication Request
        </Typography>
        <Button
          variant="contained"
          color="primary"
          onClick={sendAuthenticationRequest}
          disabled={loading || !encryptedPayload || !clientId || !clientSecret || !gstin}
          sx={{ mb: 2 }}
        >
          {loading ? 'Sending...' : 'Send Authentication Request'}
        </Button>

        {apiResponse && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6">API Response:</Typography>
            <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#e8f5e9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
              {JSON.stringify(apiResponse, null, 2)}
            </Paper>

            {apiResponse.Status === "1" ? (
              <>
                <Alert severity="success" sx={{ mt: 2 }}>
                  Authentication Successful!
                </Alert>
                <Typography variant="subtitle1" sx={{ mt: 2 }}>AuthToken:</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>
                  {apiResponse.AuthToken}
                </Paper>

                <Typography variant="subtitle1" sx={{ mt: 1 }}>TokenExpiry:</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>
                  {apiResponse.TokenExpiry}
                </Paper>

                <Typography variant="subtitle1" sx={{ mt: 1 }}>Encrypted Session Encryption Key (Sek):</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>
                  {apiResponse.Sek}
                </Paper>

                {decryptedSek && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="h6" color="primary">Decrypted Session Encryption Key (Sek):</Typography>
                    <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#c8e6c9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                      {decryptedSek}
                    </Paper>
                    <Alert severity="info" sx={{ mt: 1 }}>
                      This decrypted SEK will be used for encrypting subsequent request payloads (e.g., actual invoice data).
                    </Alert>
                  </Box>
                )}
              </>
            ) : (
              <Alert severity="warning" sx={{ mt: 2 }}>
                Authentication Failed:
                <br />
                Code: {apiResponse.ErrorDetails?.[0]?.ErrorCode} {/* Access first element of ErrorDetails array */}
                <br />
                Message: {apiResponse.ErrorDetails?.[0]?.ErrorMessage} {/* Access first element of ErrorDetails array */}
                <br />
                Info: {apiResponse.ErrorDetails?.[0]?.InfoDtls} {/* Access first element of ErrorDetails array */}
              </Alert>
            )}
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default EInvoiceAuth;