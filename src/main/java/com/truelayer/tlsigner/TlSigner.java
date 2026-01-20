package com.truelayer.tlsigner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;

import com.truelayer.signing.Signer;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.swing.*;
import java.awt.*;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.UUID;

/**
 * Montoya-based Burp extension that adds Tl-Signature to outgoing requests.
 *
 * Notes:
 * - Montoya API artifact is provided in the POM (net.portswigger.burp.extensions:montoya-api:2025.12).
 * - Uses truelayer-signing Java package for JWS construction.
 * - Uses BouncyCastle for PEM parsing.
 *
 */
public class TlSigner implements BurpExtension
{
    // Preferences keys (we use Java Preferences to avoid tying to Montoya storage API)
    private static final String PREF_NODE = "com.truelayer.montoya.tlsigner";
    private static final java.util.prefs.Preferences prefs = java.util.prefs.Preferences.userRoot().node(PREF_NODE);

    // Keys
    private static final String KEY_REQUIRE = "require_jws";
    private static final String KEY_KID = "certificate_id";
    private static final String KEY_PRIVATE_KEY = "private_key";

    // Runtime configuration (volatile for safe updates from UI thread)
    private volatile boolean requireJws;
    private volatile String certificateId;
    private volatile String privateKeyPem;
    private volatile ECPrivateKey ecPrivateKey;

    private MontoyaApi montoyaApi;

    @Override
    public void initialize(MontoyaApi montoyaApi)
    {
        this.montoyaApi = montoyaApi;
        montoyaApi.extension().setName("TrueLayer Tl-Signature (Montoya)");

        // load persisted settings from Preferences
        this.requireJws = prefs.getBoolean(KEY_REQUIRE, false);
        this.certificateId = prefs.get(KEY_KID, "");
        this.privateKeyPem = prefs.get(KEY_PRIVATE_KEY, "");
        if (this.privateKeyPem != null && !this.privateKeyPem.isEmpty()) {
            try {
                this.ecPrivateKey = loadEcPrivateKeyFromPem(this.privateKeyPem);
            } catch (Exception e) {
                montoyaApi.logging().logToError("TrueLayer Tl-Signature: failed to parse stored private key: " + e.getMessage());
                this.ecPrivateKey = null;
            }
        }

        // Register HTTP request handler
        // Note: Montoya's registerHttpRequestHandler generally accepts a HttpRequestHandler
        montoyaApi.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                try {
                    return RequestToBeSentAction.continueWith(handleRequest(requestToBeSent));
                } catch (Exception e) {
                    montoyaApi.logging().logToError("TrueLayer Tl-Signature: error signing request: " + e.getMessage());
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        // Register UI tab (Swing component)
        SwingUtilities.invokeLater(() -> {
            JPanel panel = buildUiPanel();
            // Montoya UI: add a new tab in the suite UI. If your Montoya version uses a different method name,
            // replace the call below with the Montoya API equivalent (e.g. montoyaApi.userInterface().addSuiteTab(...))
            UserInterface ui = montoyaApi.userInterface();
            ui.registerSuiteTab("TrueLayer Tl-Signature", panel);
        });

        montoyaApi.logging().logToOutput("TrueLayer Tl-Signature (Montoya) loaded. REQUIRE_JWS=" + this.requireJws);
    }

    /**
     * Core request handler: builds Tl-Signature and returns a new HttpRequest with the header added.
     */
    private HttpRequest handleRequest(HttpRequestToBeSent request) {
        if (!requireJws) {
            return request;
        }

        if (certificateId == null || certificateId.isEmpty()) {
            montoyaApi.logging().logToError("TrueLayer Tl-Signature: certificate id not configured; skipping signing.");
            return request;
        }
        if (ecPrivateKey == null) {
            montoyaApi.logging().logToError("TrueLayer Tl-Signature: private key not configured or invalid; skipping signing.");
            return request;
        }

        // Obtain method, path, headers, body
        String method = request.method();
        String path = request.path(); // might include leading "/"
        if (path == null || path.isEmpty()) path = "/";

        byte[] bodyBytes = request.body() != null ? request.body().getBytes() : new byte[0];
        String bodyString = "";
        if (bodyBytes != null && bodyBytes.length > 0) {
            try {
                bodyString = new String(bodyBytes, StandardCharsets.UTF_8);
            } catch (Exception ignored) {
                montoyaApi.logging().logToError("Error getting request body as UTF-8 string; using empty body for signing.");
                bodyString = "";
            }
        }

        String idempotencyKey = UUID.randomUUID().toString();

        String tlSignature = Signer.from(certificateId, ecPrivateKey)
                .header("Idempotency-Key", idempotencyKey)
                .method(method)
                .path(path)
                .body(bodyString)
                .sign();

        return request.withRemovedHeader("Tl-Signature")
                .withRemovedHeader("Idempotency-Key")
                .withAddedHeader("Idempotency-Key", idempotencyKey)
                .withAddedHeader("Tl-Signature", tlSignature);
    }

    /**
     * Build settings UI panel (Swing) and hook up actions to persist into Preferences.
     */
    private JPanel buildUiPanel()
    {
        JPanel mainPanel = new JPanel(new BorderLayout());
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6,6,6,6);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        JCheckBox requireCheck = new JCheckBox("Enable REQUIRE_JWS (apply signing to outgoing requests)");
        requireCheck.setSelected(this.requireJws);
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        form.add(requireCheck, gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        form.add(new JLabel("Certificate ID (kid):"), gbc);
        JTextField kidField = new JTextField();
        if (this.certificateId != null) kidField.setText(this.certificateId);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        form.add(kidField, gbc);
        gbc.weightx = 0.0;

        gbc.gridx = 0; gbc.gridy = 2;
        form.add(new JLabel("Private key (PEM):"), gbc);
        JTextArea keyArea = new JTextArea(12, 60);
        if (this.privateKeyPem != null) keyArea.setText(this.privateKeyPem);
        keyArea.setLineWrap(false);
        JScrollPane sp = new JScrollPane(keyArea);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.BOTH;
        form.add(sp, gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.0;

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton saveBtn = new JButton("Save");
        JButton validateBtn = new JButton("Validate Key");
        JLabel status = new JLabel(" ");
        bottom.add(saveBtn);
        bottom.add(validateBtn);
        bottom.add(status);

        saveBtn.addActionListener(e -> {
            boolean require = requireCheck.isSelected();
            String kid = kidField.getText().trim();
            String kpem = keyArea.getText().trim();

            if (require) {
                if (kid.isEmpty()) {
                    JOptionPane.showMessageDialog(mainPanel, "Certificate ID (kid) is required when signing is enabled.", "Validation error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (kpem.isEmpty()) {
                    JOptionPane.showMessageDialog(mainPanel, "Private key is required when signing is enabled.", "Validation error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            ECPrivateKey parsed = null;
            if (!kpem.isEmpty()) {
                try {
                    parsed = loadEcPrivateKeyFromPem(kpem);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(mainPanel, "Failed to parse private key: " + ex.getMessage(), "Key parse error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            // Persist via Preferences
            prefs.putBoolean(KEY_REQUIRE, require);
            prefs.put(KEY_KID, kid);
            prefs.put(KEY_PRIVATE_KEY, kpem);

            // Update runtime
            this.requireJws = require;
            this.certificateId = kid.isEmpty() ? null : kid;
            this.privateKeyPem = kpem.isEmpty() ? null : kpem;
            this.ecPrivateKey = parsed;

            status.setText("Saved.");
        });

        validateBtn.addActionListener(e -> {
            String kpem = keyArea.getText().trim();
            if (kpem.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel, "Paste a private key first to validate.", "No key", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            try {
                loadEcPrivateKeyFromPem(kpem);
                JOptionPane.showMessageDialog(mainPanel, "Private key parsed OK (EC private key).", "OK", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(mainPanel, "Failed to parse private key: " + ex.getMessage(), "Key parse error", JOptionPane.ERROR_MESSAGE);
            }
        });

        mainPanel.add(form, BorderLayout.CENTER);
        mainPanel.add(bottom, BorderLayout.SOUTH);
        return mainPanel;
    }

    /**
     * Load ECPrivateKey from PEM string.
     * Supports PKCS#8 ("-----BEGIN PRIVATE KEY-----") and legacy EC PRIVATE KEY / key pair blocks.
     */
    private ECPrivateKey loadEcPrivateKeyFromPem(String pem) throws Exception {
        StringReader sr = new StringReader(pem);
        PEMParser pemParser = new PEMParser(sr);
        Object object = pemParser.readObject();
        pemParser.close();

        if (object == null) {
            throw new IllegalArgumentException("No PEM object found");
        }

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

        PrivateKey pk;
        if (object instanceof PEMKeyPair) {
            pk = converter.getKeyPair((PEMKeyPair) object).getPrivate();
        } else if (object instanceof PrivateKeyInfo) {
            pk = converter.getPrivateKey((PrivateKeyInfo) object);
        } else {
            try {
                pk = converter.getPrivateKey((PrivateKeyInfo) object);
            } catch (Exception e) {
                throw new IllegalArgumentException("Unsupported PEM object: " + object.getClass().getName());
            }
        }

        if (!(pk instanceof ECPrivateKey)) {
            try {
                return (ECPrivateKey) pk;
            } catch (ClassCastException ex) {
                throw new IllegalArgumentException("Provided key is not an EC private key");
            }
        }
        return (ECPrivateKey) pk;
    }
}