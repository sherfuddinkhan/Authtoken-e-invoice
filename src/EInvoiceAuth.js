import React, { useState, useCallback, useEffect } from 'react';
import {
  Container,
  TextField,
  Button,
  Box,
  Typography,
  Paper,
  Checkbox,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
} from '@mui/material';
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

// Utility: Convert base64 string to ArrayBuffer (for internal validation/display)
function base64ToArrayBuffer(base64) {
  try {
    // btoa/atob are for browser environment. Node.js Buffer.from(base64, 'base64') would be used server-side.
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
  const [appKey, setAppKey] = useState(''); // This is YOUR generated AppKey (Base64), used for payload and SEK decryption
  const [rawAppKeyHex, setRawAppKeyHex] = useState('');
  const [rawPayloadJson, setRawPayloadJson] = useState('');
  const [base64EncodedPayload, setBase64EncodedPayload] = useState('');
  const [encryptedPayload, setEncryptedPayload] = useState('');
  const [requestHeaders, setRequestHeaders] = useState('');

  // API response and decryption
  const [apiResponse, setApiResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [receivedSek, setReceivedSek] = useState(''); // SEK received from API response
  const [decryptedSekHex, setDecryptedSekHex] = useState(''); // Decrypted SEK in Hex
  const [decryptedSekBase64, setDecryptedSekBase64] = useState(''); // Decrypted SEK in Base64

  // Automatically populate receivedSek if API response is successful
  useEffect(() => {
    console.log("--- useEffect Debug ---");
    console.log("Current apiResponse in useEffect:", apiResponse);

    if (apiResponse) {
        console.log("apiResponse exists. Status:", apiResponse.Status);
        // MODIFIED: Changed apiResponse.Status === '1' to apiResponse.Status === 1
        if (apiResponse.Status === 1) { // Check for number 1
            console.log("Status is 1 (number). Checking Data.Sek...");
            if (apiResponse.Data?.Sek) {
                console.log("Data.Sek found! Value:", apiResponse.Data.Sek);
                setReceivedSek(apiResponse.Data.Sek);
                // Clear previous decryption results if a new SEK is received
                setDecryptedSekHex('');
                setDecryptedSekBase64('');
            } else {
                console.log("Condition FAILED: apiResponse.Data.Sek is missing or invalid.");
            }
        } else {
            console.log("Condition FAILED: apiResponse.Status is NOT 1 (number). Actual Status:", apiResponse.Status);
        }
    } else {
        console.log("Condition FAILED: apiResponse is null/undefined.");
    }
  }, [apiResponse]);


  // Step 2: Generate AppKey (No master key encryption)
  const generateAndEncryptAppKey = useCallback(() => {
    try {
      const randomBytes = new Uint8Array(32);
      window.crypto.getRandomValues(randomBytes);
      setRawAppKeyHex(arrayBufferToHex(randomBytes.buffer));
      const base64AppKey = Buffer.from(randomBytes).toString('base64');
      setAppKey(base64AppKey); // Store the generated Base64 AppKey for both payload and SEK decryption
      setError(null);
    } catch (err) {
      setError(`Error generating AppKey: ${err.message}`);
      console.error('Generate AppKey Error:', err);
    }
  }, []); // No dependencies for a simple random key generation

  // Step 3: Construct and Base64 Encode Payload
  const constructAndEncodePayload = useCallback(() => {
    if (!username || !password || !appKey) { // Use appKey directly
      setError('Username, Password, and AppKey are required to construct payload.');
      return;
    }
    try {
      const payloadData = {
        Username: username,
        Password: password,
        Appkey: appKey, // Use the generated AppKey here directly
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
  }, [username, password, appKey, forceRefreshAccessToken]); // Dependency changed to appKey

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
    setReceivedSek(''); // Clear previous SEK
    setDecryptedSekHex(''); // Clear previous decryption results
    setDecryptedSekBase64('');

    const authUrl = '/eivital/v1.04/auth'; // Adjust if your API endpoint is different
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

      // Debugging logs for API response
      console.log("--- API Response Debug ---");
      console.log("Full Raw API Response from Fetch:", data);
      console.log("API Response Status:", data?.Status);
      console.log("API Response Data object:", data?.Data);
      console.log("API Response Data.Sek:", data?.Data?.Sek);


      if (!response.ok) {
        // Provide more detailed error message from API if available
        setError(data.ErrorDetails?.[0]?.ErrorMessage || `HTTP error! Status: ${response.status}`);
        return;
      }
      setApiResponse(data); // This updates the state and triggers the useEffect
      console.log("API Response successfully set to state.");

    } catch (err) {
      setError(`API Request Failed: ${err.message}`);
      console.error('API Request Error:', err);
    } finally {
      setLoading(false);
    }
  }, [encryptedPayload, clientId, clientSecret, gstin]);

  // Step 7: Decrypt Session Encryption Key (SEK)
  const decryptSek = useCallback(() => {
    setDecryptedSekHex(''); // Clear previous results
    setDecryptedSekBase64('');
    setError(null); // Clear previous errors

    // Trim inputs to remove any accidental leading/trailing whitespace
    const trimmedAppKey = appKey.trim(); // This is the AppKey generated in Step 2
    const trimmedReceivedSek = receivedSek.trim();

    console.log('--- Attempting SEK Decryption ---');
    console.log('AppKey for decryption (trimmed):', trimmedAppKey);
    console.log('Received SEK from API (trimmed):', trimmedReceivedSek);

    if (!trimmedAppKey) {
      setError('Your generated AppKey from Step 2 is required to decrypt SEK.');
      return;
    }
    if (!trimmedReceivedSek) {
      setError('The encrypted SEK from the API response is required to decrypt.');
      return;
    }

    try {
      // Validate AppKey length after Base64 decoding
      let appKeyBuffer;
      try {
          appKeyBuffer = base64ToArrayBuffer(trimmedAppKey);
      } catch (e) {
          throw new Error(`AppKey Base64 decoding failed: ${e.message}`);
      }
      if (appKeyBuffer.byteLength !== 32) {
          throw new Error(
              `Decoded AppKey must be 32 bytes (256 bits) for AES-256. Got ${appKeyBuffer.byteLength} bytes.`
          );
      }
      console.log('Decoded AppKey (Hex):', arrayBufferToHex(appKeyBuffer));


      // Validate Encrypted SEK length after Base64 decoding
      let encryptedSekBuffer;
      try {
          encryptedSekBuffer = base64ToArrayBuffer(trimmedReceivedSek);
      } catch (e) {
          throw new Error(`Encrypted SEK Base64 decoding failed: ${e.message}`);
      }
      if (encryptedSekBuffer.byteLength === 0 || encryptedSekBuffer.byteLength % 16 !== 0) {
          throw new Error(
              `Decoded Encrypted SEK length (${encryptedSekBuffer.byteLength} bytes) must be a non-zero multiple of 16 for AES-ECB decryption.`
          );
      }
      console.log('Decoded Encrypted SEK (Hex):', arrayBufferToHex(encryptedSekBuffer));


      // Convert the Base64 AppKey to a WordArray for CryptoJS
      const keyWordArray = CryptoJS.enc.Base64.parse(trimmedAppKey);

      // Decrypt the encrypted SEK (Base64 encoded)
      const decrypted = CryptoJS.AES.decrypt(trimmedReceivedSek, keyWordArray, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });

      // Convert the decrypted WordArray to a hexadecimal string
      const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);

      if (!decryptedHex) {
        // This means decryption failed or produced an empty WordArray
        throw new Error('Decryption resulted in an empty or invalid hexadecimal string. This often indicates incorrect AppKey, invalid SEK, or wrong padding/mode.');
      }

      // Convert hexadecimal to Base64
      const decryptedBase64 = CryptoJS.enc.Hex.parse(decryptedHex).toString(CryptoJS.enc.Base64);

      setDecryptedSekHex(decryptedHex);
      setDecryptedSekBase64(decryptedBase64);
      setError(null); // Ensure no error is shown if successful
      console.log('Decrypted SEK (Hex):', decryptedHex);
      console.log('Decrypted SEK (Base64):', decryptedBase64);

    } catch (err) {
      console.error('SEK Decryption Error Details:', err);
      // More specific error message for the UI
      setError(`Decryption failed: ${err.message}. Please verify the AppKey and Encrypted SEK are correct and free of extra characters.`);
      setDecryptedSekHex('Decryption Failed!');
      setDecryptedSekBase64('');
    }
  }, [appKey, receivedSek]); // Dependencies are correct

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
          <Typography variant="h6">2. Generate AppKey</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={generateAndEncryptAppKey} sx={{ mb: 2 }}>
            Generate AppKey
          </Button>
          {rawAppKeyHex && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, mb: 2, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Raw AppKey (Hex):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'purple' }}>{rawAppKeyHex}</Typography>
            </Box>
          )}
          {appKey && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Generated AppKey (Base64 - used in payload and for SEK decryption):</Typography>
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
            {apiResponse.Status === 1 ? ( // Check for number 1 here too for success message
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
          To decrypt the SEK received from the API response, you must use **your generated AppKey** (from Step 2). The E-Invoice system encrypts the SEK using a key derived from *your* AppKey.
        </Typography>
        <TextField
          label="Your Generated AppKey (Base64 Encoded)"
          value={appKey}
          fullWidth
          disabled // Disable editing as it's the generated AppKey
          helperText="This is the AppKey (from Step 2) used in your payload. It's also used to decrypt the SEK."
          sx={{ mb: 2 }}
        />
        <TextField
          label="Encrypted SEK from API Response"
          value={receivedSek}
          fullWidth
          disabled // Disable editing as it's from API response
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
        {/* Display "Decryption Failed!" explicitly */}
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