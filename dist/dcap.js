// Keep the package name indirect so TypeScript and browser bundlers do not
// require an optional peer dependency unless the verifier is actually used.
async function loadPhala() {
    const packageName = '@phala/dcap-qvl';
    try {
        return await import(packageName);
    }
    catch {
        throw new Error('@phala/dcap-qvl is required for DCAP verification. Install it: npm install @phala/dcap-qvl');
    }
}
/**
 * Create a DCAP verifier backed by @phala/dcap-qvl.
 *
 * Performs full Intel TDX DCAP verification:
 * - PCK certificate chain validation up to Intel SGX Root CA
 * - Quote signature verification (ECDSA P-256)
 * - QE identity validation
 * - TCB level evaluation
 * - CRL checking
 *
 * @param pccsUrl - PCCS server URL for collateral fetching. Default: Phala PCCS (https://pccs.phala.network)
 */
export function createDcapVerifier(pccsUrl) {
    return async (quoteBytes) => {
        const phala = await loadPhala();
        const url = pccsUrl ?? phala.PHALA_PCCS_URL;
        const result = await phala.getCollateralAndVerify(quoteBytes, url);
        return {
            status: String(result.status),
            advisoryIds: Array.isArray(result.advisory_ids)
                ? result.advisory_ids.map(String)
                : [],
        };
    };
}
//# sourceMappingURL=dcap.js.map