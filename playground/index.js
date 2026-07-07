import init, {
    ml_kem_768_keygen,
    ml_kem_768_encapsulate,
    ml_kem_768_decapsulate,
    ml_dsa_65_keygen,
    ml_dsa_65_sign,
    ml_dsa_65_verify,
    slh_dsa_128s_keygen,
    slh_dsa_128s_sign,
    slh_dsa_128s_verify
} from '../pqcrypto-wasm/pkg/pqcrypto_wasm.js';

// ============================================================================
// Encoding / Decoding Helper Functions
// ============================================================================

function hexToBytes(hex) {
    hex = hex.trim().replace(/\s+/g, '');
    if (hex.length % 2 !== 0) throw new Error("Hex string must have an even length");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        const byte = parseInt(hex.substr(i * 2, 2), 16);
        if (isNaN(byte)) throw new Error("Invalid hex character");
        bytes[i] = byte;
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64ToBytes(b64) {
    b64 = b64.trim().replace(/\s+/g, '');
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function bytesToB64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function convertValue(val, targetEncoding) {
    if (!val || !val.trim()) return '';
    const trimmed = val.trim().replace(/\s+/g, '');
    try {
        if (targetEncoding === 'base64') {
            if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
                return bytesToB64(hexToBytes(trimmed));
            }
            return val;
        } else {
            try {
                if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
                    return val;
                }
                return bytesToHex(b64ToBytes(trimmed));
            } catch (e) {
                return val;
            }
        }
    } catch (e) {
        return val;
    }
}

// ============================================================================
// Input Validation Helper
// ============================================================================

function validateAndTrim(val, label, expectedByteLen) {
    if (!val || !val.trim()) {
        throw new Error(`${label} is required.`);
    }
    const trimmed = val.trim().replace(/\s+/g, '');
    let bytes;
    const isHexStr = /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0;

    if (isHexStr) {
        try {
            bytes = hexToBytes(trimmed);
        } catch (e) {
            throw new Error(`${label} is not a valid hex string.`);
        }
    } else {
        try {
            bytes = b64ToBytes(trimmed);
        } catch (e) {
            throw new Error(`${label} must be a valid HEX or BASE64 string.`);
        }
    }

    if (bytes.length !== expectedByteLen) {
        throw new Error(`${label} length is invalid. Expected ${expectedByteLen} bytes, but got ${bytes.length} bytes.`);
    }

    return trimmed;
}

// ============================================================================
// UI Controllers & State
// ============================================================================

let currentEncoding = 'hex';

// Alert Banner Controller
const alertBanner = document.getElementById('alert-banner');
const alertMessage = document.getElementById('alert-message');
const alertClose = document.getElementById('alert-close');

function showAlert(message, type = 'error') {
    alertMessage.textContent = message;
    alertBanner.className = `alert-banner ${type}`;
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function hideAlert() {
    alertBanner.classList.add('hidden');
}

alertClose.addEventListener('click', hideAlert);

// Tab Switching Controller
const tabButtons = document.querySelectorAll('.tab-link');
const tabPanels = document.querySelectorAll('.tab-panel');

tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        
        tabButtons.forEach(b => {
            b.classList.remove('active');
            b.setAttribute('aria-selected', 'false');
        });
        tabPanels.forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');
        document.getElementById(targetTab).classList.add('active');
        hideAlert();
    });
});

// Encoding Format Toggler
const encodingButtons = document.querySelectorAll('.encoding-btn');
const translatableFields = [
    'kem-pk-out', 'kem-sk-out', 'kem-pk-encap', 'kem-ct-out', 'kem-ss-encap', 'kem-sk-decap', 'kem-ct-decap', 'kem-ss-decap',
    'dsa-pk-out', 'dsa-sk-out', 'dsa-sk-sign', 'dsa-sig-out', 'dsa-pk-verify', 'dsa-sig-verify',
    'slh-pk-out', 'slh-sk-out', 'slh-sk-sign', 'slh-sig-out', 'slh-pk-verify', 'slh-sig-verify'
];

encodingButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const targetEncoding = btn.getAttribute('data-encoding');
        if (targetEncoding === currentEncoding) return;

        encodingButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Translate values in all cryptographic input/output textareas
        translatableFields.forEach(id => {
            const el = document.getElementById(id);
            if (el && el.value) {
                el.value = convertValue(el.value, targetEncoding);
            }
        });

        currentEncoding = targetEncoding;
    });
});

// Copy to Clipboard Controller
const copyButtons = document.querySelectorAll('.copy-btn');
copyButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
        const targetId = btn.getAttribute('data-target');
        const targetEl = document.getElementById(targetId);
        if (!targetEl || !targetEl.value) return;

        try {
            await navigator.clipboard.writeText(targetEl.value);
            
            const originalHTML = btn.innerHTML;
            btn.classList.add('copied');
            btn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                <span class="copy-text">Copied!</span>
            `;

            setTimeout(() => {
                btn.classList.remove('copied');
                btn.innerHTML = originalHTML;
            }, 2000);
        } catch (err) {
            showAlert("Failed to copy text to clipboard.", 'error');
        }
    });
});

// ============================================================================
// WASM Cryptographic Bindings
// ============================================================================

async function runPlayground() {
    try {
        // Initialize the WASM module
        await init();
        console.log("PQCrypto WASM module initialized successfully.");
    } catch (e) {
        showAlert("Failed to load WebAssembly cryptographic module. Make sure pqcrypto-wasm is built.", 'error');
        console.error("WASM init error:", e);
        return;
    }

    // --- ML-KEM-768 Bindings ---
    const kemKeygenBtn = document.getElementById('kem-keygen-btn');
    const kemEncapBtn = document.getElementById('kem-encap-btn');
    const kemDecapBtn = document.getElementById('kem-decap-btn');

    kemKeygenBtn.addEventListener('click', () => {
        hideAlert();
        try {
            const keypair = ml_kem_768_keygen();
            let pk = keypair.public_key;
            let sk = keypair.secret_key;

            if (currentEncoding === 'base64') {
                pk = convertValue(pk, 'base64');
                sk = convertValue(sk, 'base64');
            }

            document.getElementById('kem-pk-out').value = pk;
            document.getElementById('kem-sk-out').value = sk;
            
            // Clear outputs of other operations
            document.getElementById('kem-ct-out').value = '';
            document.getElementById('kem-ss-encap').value = '';
            document.getElementById('kem-ss-decap').value = '';
        } catch (err) {
            showAlert(`Key Generation Error: ${err.message || err}`, 'error');
        }
    });

    kemEncapBtn.addEventListener('click', () => {
        hideAlert();
        try {
            // Autofill helper
            let pkVal = document.getElementById('kem-pk-encap').value;
            if (!pkVal.trim()) {
                const generatedPk = document.getElementById('kem-pk-out').value;
                if (generatedPk.trim()) {
                    pkVal = generatedPk;
                    document.getElementById('kem-pk-encap').value = pkVal;
                }
            }

            const pk = validateAndTrim(pkVal, "Recipient Public Key (pk)", 1184);
            const result = ml_kem_768_encapsulate(pk);

            document.getElementById('kem-ct-out').value = result.ciphertext;
            document.getElementById('kem-ss-encap').value = result.shared_secret;
        } catch (err) {
            showAlert(`Encapsulation Error: ${err.message || err}`, 'error');
        }
    });

    kemDecapBtn.addEventListener('click', () => {
        hideAlert();
        try {
            // Autofill helpers
            let skVal = document.getElementById('kem-sk-decap').value;
            if (!skVal.trim()) {
                const generatedSk = document.getElementById('kem-sk-out').value;
                if (generatedSk.trim()) {
                    skVal = generatedSk;
                    document.getElementById('kem-sk-decap').value = skVal;
                }
            }

            let ctVal = document.getElementById('kem-ct-decap').value;
            if (!ctVal.trim()) {
                const generatedCt = document.getElementById('kem-ct-out').value;
                if (generatedCt.trim()) {
                    ctVal = generatedCt;
                    document.getElementById('kem-ct-decap').value = ctVal;
                }
            }

            const sk = validateAndTrim(skVal, "Secret Key (sk)", 2400);
            const ct = validateAndTrim(ctVal, "Ciphertext (ct)", 1088);

            const sharedSecret = ml_kem_768_decapsulate(sk, ct);
            document.getElementById('kem-ss-decap').value = sharedSecret;
        } catch (err) {
            showAlert(`Decapsulation Error: ${err.message || err}`, 'error');
        }
    });

    // --- ML-DSA-65 Bindings ---
    const dsaKeygenBtn = document.getElementById('dsa-keygen-btn');
    const dsaSignBtn = document.getElementById('dsa-sign-btn');
    const dsaVerifyBtn = document.getElementById('dsa-verify-btn');
    const dsaVerifyStatus = document.getElementById('dsa-verify-status');

    dsaKeygenBtn.addEventListener('click', () => {
        hideAlert();
        try {
            const keypair = ml_dsa_65_keygen();
            let pk = keypair.public_key;
            let sk = keypair.secret_key;

            if (currentEncoding === 'base64') {
                pk = convertValue(pk, 'base64');
                sk = convertValue(sk, 'base64');
            }

            document.getElementById('dsa-pk-out').value = pk;
            document.getElementById('dsa-sk-out').value = sk;
            
            // Clear outputs of other operations
            document.getElementById('dsa-sig-out').value = '';
            dsaVerifyStatus.className = 'verify-status hidden';
        } catch (err) {
            showAlert(`Key Generation Error: ${err.message || err}`, 'error');
        }
    });

    dsaSignBtn.addEventListener('click', () => {
        hideAlert();
        try {
            let skVal = document.getElementById('dsa-sk-sign').value;
            if (!skVal.trim()) {
                const generatedSk = document.getElementById('dsa-sk-out').value;
                if (generatedSk.trim()) {
                    skVal = generatedSk;
                    document.getElementById('dsa-sk-sign').value = skVal;
                }
            }

            const sk = validateAndTrim(skVal, "Secret Key (sk)", 2912);
            const msgText = document.getElementById('dsa-msg-sign').value;
            const msgBytes = new TextEncoder().encode(msgText);

            const sig = ml_dsa_65_sign(sk, msgBytes);
            document.getElementById('dsa-sig-out').value = sig;
        } catch (err) {
            showAlert(`Signing Error: ${err.message || err}`, 'error');
        }
    });

    dsaVerifyBtn.addEventListener('click', () => {
        hideAlert();
        dsaVerifyStatus.className = 'verify-status hidden';
        try {
            let pkVal = document.getElementById('dsa-pk-verify').value;
            if (!pkVal.trim()) {
                const generatedPk = document.getElementById('dsa-pk-out').value;
                if (generatedPk.trim()) {
                    pkVal = generatedPk;
                    document.getElementById('dsa-pk-verify').value = pkVal;
                }
            }

            let msgText = document.getElementById('dsa-msg-verify').value;
            if (!msgText.trim()) {
                const signMsg = document.getElementById('dsa-msg-sign').value;
                if (signMsg.trim()) {
                    msgText = signMsg;
                    document.getElementById('dsa-msg-verify').value = msgText;
                }
            }

            let sigVal = document.getElementById('dsa-sig-verify').value;
            if (!sigVal.trim()) {
                const generatedSig = document.getElementById('dsa-sig-out').value;
                if (generatedSig.trim()) {
                    sigVal = generatedSig;
                    document.getElementById('dsa-sig-verify').value = sigVal;
                }
            }

            const pk = validateAndTrim(pkVal, "Public Key (pk)", 1952);
            const sig = validateAndTrim(sigVal, "Signature", 6688);
            const msgBytes = new TextEncoder().encode(msgText);

            const isValid = ml_dsa_65_verify(pk, msgBytes, sig);
            
            dsaVerifyStatus.className = 'verify-status';
            if (isValid) {
                dsaVerifyStatus.classList.add('success');
                dsaVerifyStatus.querySelector('.status-icon').innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
                dsaVerifyStatus.querySelector('.status-text').textContent = 'Signature is VALID';
            } else {
                dsaVerifyStatus.classList.add('failure');
                dsaVerifyStatus.querySelector('.status-icon').innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
                dsaVerifyStatus.querySelector('.status-text').textContent = 'Signature is INVALID';
            }
        } catch (err) {
            showAlert(`Verification Error: ${err.message || err}`, 'error');
        }
    });

    // --- SLH-DSA-SHA2-128s Bindings ---
    const slhKeygenBtn = document.getElementById('slh-keygen-btn');
    const slhSignBtn = document.getElementById('slh-sign-btn');
    const slhVerifyBtn = document.getElementById('slh-verify-btn');
    const slhVerifyStatus = document.getElementById('slh-verify-status');

    slhKeygenBtn.addEventListener('click', () => {
        hideAlert();
        try {
            const keypair = slh_dsa_128s_keygen();
            let pk = keypair.public_key;
            let sk = keypair.secret_key;

            if (currentEncoding === 'base64') {
                pk = convertValue(pk, 'base64');
                sk = convertValue(sk, 'base64');
            }

            document.getElementById('slh-pk-out').value = pk;
            document.getElementById('slh-sk-out').value = sk;
            
            // Clear outputs of other operations
            document.getElementById('slh-sig-out').value = '';
            slhVerifyStatus.className = 'verify-status hidden';
        } catch (err) {
            showAlert(`Key Generation Error: ${err.message || err}`, 'error');
        }
    });

    slhSignBtn.addEventListener('click', () => {
        hideAlert();
        // Give visual indicator of working since SLH is slow
        slhSignBtn.disabled = true;
        const originalText = slhSignBtn.textContent;
        slhSignBtn.textContent = 'Computing Signature (please wait)...';

        setTimeout(() => {
            try {
                let skVal = document.getElementById('slh-sk-sign').value;
                if (!skVal.trim()) {
                    const generatedSk = document.getElementById('slh-sk-out').value;
                    if (generatedSk.trim()) {
                        skVal = generatedSk;
                        document.getElementById('slh-sk-sign').value = skVal;
                    }
                }

                const sk = validateAndTrim(skVal, "Secret Key (sk)", 64);
                const msgText = document.getElementById('slh-msg-sign').value;
                const msgBytes = new TextEncoder().encode(msgText);

                const sig = slh_dsa_128s_sign(sk, msgBytes);
                document.getElementById('slh-sig-out').value = sig;
            } catch (err) {
                showAlert(`Signing Error: ${err.message || err}`, 'error');
            } finally {
                slhSignBtn.disabled = false;
                slhSignBtn.textContent = originalText;
            }
        }, 50); // SetTimeout to let UI paint loading state
    });

    slhVerifyBtn.addEventListener('click', () => {
        hideAlert();
        slhVerifyStatus.className = 'verify-status hidden';
        slhVerifyBtn.disabled = true;
        const originalText = slhVerifyBtn.textContent;
        slhVerifyBtn.textContent = 'Verifying (please wait)...';

        setTimeout(() => {
            try {
                let pkVal = document.getElementById('slh-pk-verify').value;
                if (!pkVal.trim()) {
                    const generatedPk = document.getElementById('slh-pk-out').value;
                    if (generatedPk.trim()) {
                        pkVal = generatedPk;
                        document.getElementById('slh-pk-verify').value = pkVal;
                    }
                }

                let msgText = document.getElementById('slh-msg-verify').value;
                if (!msgText.trim()) {
                    const signMsg = document.getElementById('slh-msg-sign').value;
                    if (signMsg.trim()) {
                        msgText = signMsg;
                        document.getElementById('slh-msg-verify').value = msgText;
                    }
                }

                let sigVal = document.getElementById('slh-sig-verify').value;
                if (!sigVal.trim()) {
                    const generatedSig = document.getElementById('slh-sig-out').value;
                    if (generatedSig.trim()) {
                        sigVal = generatedSig;
                        document.getElementById('slh-sig-verify').value = sigVal;
                    }
                }

                const pk = validateAndTrim(pkVal, "Public Key (pk)", 32);
                const sig = validateAndTrim(sigVal, "Signature", 7836);
                const msgBytes = new TextEncoder().encode(msgText);

                const isValid = slh_dsa_128s_verify(pk, msgBytes, sig);
                
                slhVerifyStatus.className = 'verify-status';
                if (isValid) {
                    slhVerifyStatus.classList.add('success');
                    slhVerifyStatus.querySelector('.status-icon').innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
                    slhVerifyStatus.querySelector('.status-text').textContent = 'Signature is VALID';
                } else {
                    slhVerifyStatus.classList.add('failure');
                    slhVerifyStatus.querySelector('.status-icon').innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
                    slhVerifyStatus.querySelector('.status-text').textContent = 'Signature is INVALID';
                }
            } catch (err) {
                showAlert(`Verification Error: ${err.message || err}`, 'error');
            } finally {
                slhVerifyBtn.disabled = false;
                slhVerifyBtn.textContent = originalText;
            }
        }, 50);
    });
}

// Run the application
runPlayground();
