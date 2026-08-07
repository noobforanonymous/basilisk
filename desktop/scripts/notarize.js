const path = require('path');
const { notarize } = require('@electron/notarize');

exports.default = async function notarizeApp(context) {
    if (context.electronPlatformName !== 'darwin') {
        return;
    }
    if (process.env.BASILISK_SKIP_NOTARIZE === '1') {
        console.log('[notarize] Skipping notarization for the non-release upgrade fixture.');
        return;
    }

    const appPath = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
    const teamId = process.env.APPLE_TEAM_ID;
    if (!teamId) {
        if (process.env.BASILISK_REQUIRE_VENDOR_TRUST === 'true') {
            throw new Error('Tagged release requires APPLE_TEAM_ID and notarization credentials.');
        }
        console.log('[notarize] APPLE_TEAM_ID not configured, skipping notarization for preview build.');
        return;
    }

    const apiKey = process.env.APPLE_API_KEY;
    const apiKeyId = process.env.APPLE_API_KEY_ID;
    const apiIssuer = process.env.APPLE_API_ISSUER;
    if (apiKey && apiKeyId && apiIssuer) {
        console.log(`[notarize] Submitting ${appPath} using App Store Connect API key.`);
        await notarize({
            appPath,
            appleApiKey: apiKey,
            appleApiKeyId: apiKeyId,
            appleApiIssuer: apiIssuer,
            teamId,
        });
        return;
    }

    const appleId = process.env.APPLE_ID;
    const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
    if (appleId && appleIdPassword) {
        console.log(`[notarize] Submitting ${appPath} using Apple ID credentials.`);
        await notarize({
            appPath,
            appleId,
            appleIdPassword,
            teamId,
        });
        return;
    }

    if (process.env.BASILISK_REQUIRE_VENDOR_TRUST === 'true') {
        throw new Error('Tagged release requires Apple notarization credentials.');
    }
    console.log('[notarize] Apple notarization credentials not configured, skipping preview notarization.');
};
