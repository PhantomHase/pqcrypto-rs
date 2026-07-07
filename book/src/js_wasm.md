# JavaScript & WebAssembly Integration

PQCrypto-RS provides native support for WebAssembly environments, allowing post-quantum cryptography to run inside modern web browsers or Node.js runtimes.

## Crate: `pqcrypto-wasm`
The wrapper crate `pqcrypto-wasm` contains the `wasm-bindgen` bindings.

## Compilation Target
To build the WASM package for direct loading in the browser via ES modules, run:
```bash
wasm-pack build pqcrypto-wasm --target web
```
This produces a `pkg/` directory containing the JavaScript facade (`pqcrypto_wasm.js`) and compiled WebAssembly binary (`pqcrypto_wasm_bg.wasm`).

## Loading in the Browser
You can load the module directly from an HTML file:
```html
<script type="module">
    import init, { ml_kem_768_keygen, ml_kem_768_encapsulate } from "./pkg/pqcrypto_wasm.js";

    async function start() {
        // Initialize WASM binary
        await init();

        // 1. Generate keys (returns keys encoded in Hex)
        const keyPair = ml_kem_768_keygen();
        console.log("Public Key (Hex):", keyPair.public_key);
        console.log("Secret Key (Hex):", keyPair.secret_key);

        // 2. Encapsulate
        const encapsResult = ml_kem_768_encapsulate(keyPair.public_key);
        console.log("Ciphertext (Hex):", encapsResult.ciphertext);
        console.log("Shared Secret (Hex):", encapsResult.shared_secret);
    }

    start();
</script>
```

## Input and Output formats
All public JS binding functions accept keys/signatures/ciphertexts in **either Hex or Base64** format (automatically detected) and output their results in matching formats for user convenience.
- **Keygen**: Returns Hex-encoded keys.
- **Encap/Sign**: Encodes output ciphertext/signatures based on input format (if input public/secret key is Base64, outputs are Base64; if input is Hex, outputs are Hex).
