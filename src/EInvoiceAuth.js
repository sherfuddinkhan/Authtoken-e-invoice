import React, { useState, useCallback, useEffect } from 'react';
import {Container,TextField,Button,Box,Typography,Paper,Checkbox,FormControlLabel,Accordion,AccordionSummary,AccordionDetails,Alert,} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import JSEncrypt from 'jsencrypt';
import { Buffer } from 'buffer';
import CryptoJS from 'crypto-js';

// Polyfill Buffer for browser environments
if (typeof window !== 'undefined' && !window.Buffer) {
  window.Buffer = Buffer;
}

// Utility: Convert ArrayBuffer to hexadecimal string
function arrayBufferToHex(buffer) {
  const byteArray = new Uint8Array(buffer);
  const hexParts = [];
  byteArray.forEach(byte => {
    const hex = byte.toString(16);
    hexParts.push(hex.length === 1 ? '0' + hex : hex);
  });
  return hexParts.join('');
}

// Utility: Convert base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
  try {
    const binaryString = atob(base64);
    const length = binaryString.length;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    console.error("Error decoding Base64 to ArrayBuffer:", e);
    throw new Error("Invalid Base64 string for ArrayBuffer conversion.");
  }
}

// Utility: Convert CryptoJS WordArray to Hex string for display
function convertWordArrayToHex(wordArray) {
  const hexString = CryptoJS.enc.Hex.stringify(wordArray);
  return hexString;
}

const EInvoiceAuth = () => {
  // Input fields
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [gstin, setGstin] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [eInvoicePublicKey, setEInvoicePublicKey] = useState('');
  const [forceRefreshAccessToken, setForceRefreshAccessToken] = useState(false);

  // Generated/intermediate values
  const [appKey, setAppKey] = useState(''); // Base64-encoded 256-bit AppKey
  const [rawAppKeyHex, setRawAppKeyHex] = useState('');
  const [rawPayloadJson, setRawPayloadJson] = useState('');
  const [base64EncodedPayload, setBase64EncodedPayload] = useState('');
  const [encryptedPayload, setEncryptedPayload] = useState('');
  const [requestHeaders, setRequestHeaders] = useState('');

  // API response and decryption
  const [apiResponse, setApiResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [receivedSek, setReceivedSek] = useState('');
  const [decryptedSekHex, setDecryptedSekHex] = useState('');
  const [decryptedSekBase64, setDecryptedSekBase64] = useState('');

  // Decryption process visibility
  const [trimmedAppKey, setTrimmedAppKey] = useState('');
  const [trimmedReceivedSek, setTrimmedReceivedSek] = useState('');
  const [keyWordArrayHex, setKeyWordArrayHex] = useState('');
  const [receivedSekHex, setReceivedSekHex] = useState('');

  // Automatically populate receivedSek if API response is successful
  useEffect(() => {
    if (apiResponse && apiResponse.Status === 1 && apiResponse.Data?.Sek) {
      setReceivedSek(apiResponse.Data.Sek);
      setDecryptedSekHex('');
      setDecryptedSekBase64('');
    }
  }, [apiResponse]);

  // Step 2: Generate 256-bit AppKey
  const generateAndEncryptAppKey = useCallback(() => {
    try {
      // Generate a 256-bit (32-byte) random key
      const randomBytes = new Uint8Array(32); // 32 bytes = 256 bits
      window.crypto.getRandomValues(randomBytes);
      
      // Validate key length
      if (randomBytes.length !== 32) {
        throw new Error(`Generated key length is ${randomBytes.length} bytes, expected 32 bytes (256 bits).`);
      }

      // Convert to hex for display
      const hexKey = arrayBufferToHex(randomBytes.buffer);
      setRawAppKeyHex(hexKey);

      // Convert to Base64 for payload and SEK decryption
      const base64AppKey = Buffer.from(randomBytes).toString('base64');
      setAppKey(base64AppKey);
      setError(null);
    } catch (err) {
      setError(`Error generating 256-bit AppKey: ${err.message}`);
      console.error('Generate AppKey Error:', err);
    }
  }, []);

  // Step 3: Construct and Base64 Encode Payload
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
      console.error('Payload Construction Error:', err);
    }
  }, [username, password, appKey, forceRefreshAccessToken]);

  // Step 4: Encrypt Payload
  const encryptPayload = useCallback(() => {
    if (!base64EncodedPayload || !eInvoicePublicKey) {
      setError('Base64 Encoded Payload and Public Key are required for encryption.');
      return;
    }
    try {
      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(eInvoicePublicKey);
      const encrypted = encrypt.encrypt(base64EncodedPayload);
      if (!encrypted) {
        throw new Error('Encryption failed. Check public key format and payload size.');
      }
      setEncryptedPayload(encrypted);
      setError(null);
    } catch (err) {
      setError(`Error encrypting payload: ${err.message}. Ensure public key is valid and in PEM format.`);
      console.error('Encryption Error:', err);
    }
  }, [base64EncodedPayload, eInvoicePublicKey]);

  // Step 5: Construct Request Headers
  const constructHeaders = useCallback(() => {
    if (!clientId || !clientSecret || !gstin) {
      setError('Client ID, Client Secret, and GSTIN are required for headers.');
      return;
    }
    const headers = {
      client_id: clientId,
      client_secret: clientSecret,
      Gstin: gstin,
      'Content-Type': 'application/json',
    };
    setRequestHeaders(JSON.stringify(headers, null, 2));
    setError(null);
  }, [clientId, clientSecret, gstin]);

  // Step 6: Send Authentication Request
  const sendAuthenticationRequest = useCallback(async () => {
    if (!encryptedPayload || !clientId || !clientSecret || !gstin) {
      setError('All prerequisite steps (AppKey, Payload, Encryption, Headers) must be completed.');
      return;
    }
    setLoading(true);
    setError(null);
    setApiResponse(null);
    setReceivedSek('');
    setDecryptedSekHex('');
    setDecryptedSekBase64('');
    setTrimmedAppKey('');
    setTrimmedReceivedSek('');
    setKeyWordArrayHex('');
    setReceivedSekHex('');

    const authUrl = '/eivital/v1.04/auth';
    const requestBody = {
      Data: encryptedPayload,
    };

    try {
      const headers = {
        client_id: clientId,
        client_secret: clientSecret,
        Gstin: gstin,
        'Content-Type': 'application/json',
      };
      const response = await fetch(authUrl, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(requestBody),
      });
      const data = await response.json();

      if (!response.ok) {
        setError(data.ErrorDetails?.[0]?.ErrorMessage || `HTTP error! Status: ${response.status}`);
        return;
      }
      setApiResponse(data);
    } catch (err) {
      setError(`API Request Failed: ${err.message}`);
      console.error('API Request Error:', err);
    } finally {
      setLoading(false);
    }
  }, [encryptedPayload, clientId, clientSecret, gstin]);

  // Step 7: Decrypt Session Encryption Key (SEK)
  const decryptSek = useCallback(() => {
    setDecryptedSekHex('');
    setDecryptedSekBase64('');
    setError(null);
    setReceivedSekHex('');

    const newTrimmedAppKey = appKey.trim();
    const newTrimmedReceivedSek = receivedSek.trim();

    setTrimmedAppKey(newTrimmedAppKey);
    setTrimmedReceivedSek(newTrimmedReceivedSek);

    if (!newTrimmedAppKey) {
      setError('Your generated AppKey from Step 2 is required to decrypt SEK.');
      return;
    }
    if (!newTrimmedReceivedSek) {
      setError('The encrypted SEK from the API response is required to decrypt.');
      return;
    }

    try {
      let appKeyBuffer;
      try {
        appKeyBuffer = base64ToArrayBuffer(newTrimmedAppKey);
      } catch (e) {
        throw new Error(`AppKey Base64 decoding failed: ${e.message}`);
      }
      if (appKeyBuffer.byteLength !== 32) {
        throw new Error(
          `Decoded AppKey must be 32 bytes (256 bits). Got ${appKeyBuffer.byteLength} bytes.`
        );
      }
      let encryptedSekBuffer;
      try {
        encryptedSekBuffer = base64ToArrayBuffer(newTrimmedReceivedSek);
      } catch (e) {
        throw new Error(`Encrypted SEK Base64 decoding failed: ${e.message}`);
      }
      if (encryptedSekBuffer.byteLength === 0 || encryptedSekBuffer.byteLength % 16 !== 0) {
        throw new Error(
          `Decoded Encrypted SEK length (${encryptedSekBuffer.byteLength} bytes) must be a non-zero multiple of 16 for AES-ECB decryption.`
        );
      }

      const keyWordArray = CryptoJS.enc.Base64.parse(newTrimmedAppKey);
      setKeyWordArrayHex(convertWordArrayToHex(keyWordArray));

      const encryptedSekWordArray = CryptoJS.enc.Base64.parse(newTrimmedReceivedSek);
      setReceivedSekHex(convertWordArrayToHex(encryptedSekWordArray));

      const decrypted = CryptoJS.AES.decrypt(newTrimmedReceivedSek, keyWordArray, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });

      const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);
      if (!decryptedHex) {
        throw new Error('Decryption resulted in an empty or invalid hexadecimal string.');
      }

      const decryptedBase64 = CryptoJS.enc.Hex.parse(decryptedHex).toString(CryptoJS.enc.Base64);
      setDecryptedSekHex(decryptedHex);
      setDecryptedSekBase64(decryptedBase64);
      setError(null);
    } catch (err) {
      console.error('SEK Decryption Error Details:', err);
      setError(`Decryption failed: ${err.message}. Please verify the AppKey and Encrypted SEK.`);
      setDecryptedSekHex('Decryption Failed!');
      setDecryptedSekBase64('');
    }
  }, [appKey, receivedSek]);

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

      {/* Step 1: Input Parameters */}
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

      {/* Step 2: Generate AppKey */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">2. Generate 256-bit AppKey</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={generateAndEncryptAppKey} sx={{ mb: 2 }}>
            Generate AppKey
          </Button>
          {rawAppKeyHex && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, mb: 2, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Raw AppKey (Hex, 256 bits):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'purple' }}>{rawAppKeyHex}</Typography>
            </Box>
          )}
          {appKey && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Generated AppKey (Base64, 256 bits):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'green' }}>{appKey}</Typography>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Step 3: Construct and Encode Payload */}
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

      {/* Step 4: Encrypt Payload */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">4. Encrypt Base64 Encoded Payload</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={encryptPayload} sx={{ mb: 2 }}>
            Encrypt Payload with Public Key
          </Button>
          {encryptedPayload && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Encrypted Payload (Data field):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'blue' }}>{encryptedPayload}</Typography>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Step 5: Construct Request Headers */}
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">5. Construct Request Headers</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={constructHeaders} sx={{ mb: 2 }}>
            Construct Headers
          </Button>
          {requestHeaders && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1 }}>
              <Typography variant="subtitle1">Request Headers:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                {requestHeaders}
              </Paper>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Step 6: Send Authentication Request */}
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
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
            {apiResponse.Status === 1 ? (
              <>
                <Alert severity="success" sx={{ mt: 2 }}>
                  Authentication Successful!
                </Alert>
                <Typography variant="subtitle1" sx={{ mt: 2 }}>AuthToken:</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>
                  {apiResponse.Data.AuthToken}
                </Paper>
                <Typography variant="subtitle1" sx={{ mt: 1 }}>TokenExpiry:</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>
                  {apiResponse.Data.TokenExpiry}
                </Paper>
                <Typography variant="subtitle1" sx={{ mt: 1 }}>Encrypted Session Encryption Key (Sek):</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>
                  {apiResponse.Data.Sek}
                </Paper>
              </>
            ) : (
              <Alert severity="warning" sx={{ mt: 2 }}>
                Authentication Failed:
                <br />
                Code: {apiResponse.ErrorDetails?.[0]?.ErrorCode}
                <br />
                Message: {apiResponse.ErrorDetails?.[0]?.ErrorMessage}
                <br />
                Info: {apiResponse.ErrorDetails?.[0]?.InfoDtls}
              </Alert>
            )}
          </Box>
        )}
      </Paper>

      {/* Step 7: Decrypt Session Encryption Key (SEK) */}
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h5" gutterBottom>
          7. Decrypt Session Encryption Key (SEK)
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          To decrypt the SEK received from the API response, you must use **your generated 256-bit AppKey** (from Step 2).
        </Typography>
        <TextField
          label="Your Generated AppKey (Base64 Encoded, 256 bits)"
          value={appKey}
          fullWidth
          disabled
          helperText="This is the 256-bit AppKey (from Step 2) used in your payload and to decrypt the SEK."
          sx={{ mb: 2 }}
        />
        <TextField
          label="Encrypted SEK from API Response"
          value={receivedSek}
          fullWidth
          disabled
          helperText="This is the 'Sek' value received directly from the API response in Step 6."
          sx={{ mb: 2 }}
        />
        <Button
          variant="contained"
          onClick={decryptSek}
          disabled={!appKey || !receivedSek}
          sx={{ mb: 2 }}
        >
          Decrypt SEK
        </Button>

        {(!appKey || !receivedSek) && (
          <Typography color="error" variant="body2" sx={{ mb: 2 }}>
            Ensure you have generated an AppKey (Step 2) and successfully received an API response with SEK (Step 6).
          </Typography>
        )}
        {trimmedAppKey && (
          <Box sx={{ backgroundColor: '#fff8e1', p: 2, borderRadius: 1, mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Trimmed AppKey (256 bits):</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // 32-byte (256-bit) symmetric key, generated randomly, encoded in Base64.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace', mb: 2 }}>{trimmedAppKey}</Typography>
            
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Trimmed Received SEK:</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // Encrypted Session Encryption Key (SEK) from the e-invoice API, Base64-encoded.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace', mb: 2 }}>{trimmedReceivedSek}</Typography>
            
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Decryption Key (Hex, 256 bits):</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // 256-bit AppKey in hex, used with AES-256-ECB for SEK decryption.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace', mb: 2 }}>{keyWordArrayHex}</Typography>
            
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Encrypted Data (Received SEK) (Hex):</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // Base64-decoded SEK in hex, to be decrypted with the AppKey.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace' }}>{receivedSekHex}</Typography>
          </Box>
        )}
        
        {decryptedSekHex && decryptedSekHex !== 'Decryption Failed!' && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" color="primary">Decrypted Session Encryption Key (SEK):</Typography>
            <div>
              <Typography variant="subtitle1" sx={{ mt: 1 }}>Hexadecimal:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#c8e6c9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                {decryptedSekHex}
              </Paper>
            </div>
            <div>
              <Typography variant="subtitle1" sx={{ mt: 1 }}>Base64:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#c8e6c9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                {decryptedSekBase64}
              </Paper>
            </div>
            <Alert severity="info" sx={{ mt: 1 }}>
              This decrypted SEK is crucial for encrypting subsequent e-invoice request payloads (e.g., generating IRN).
            </Alert>
          </Box>
        )}
        {decryptedSekHex === 'Decryption Failed!' && (
          <Paper variant="outlined" sx={{ p: 2, mt: 2, backgroundColor: '#ffebee', border: '1px solid #ef9a9a', wordBreak: 'break-all' }}>
            <Typography variant="subtitle1" color="error">Decryption Failed!</Typography>
          </Paper>
        )}
      </Paper>
    </Container>
  );
};

export default EInvoiceAuth;