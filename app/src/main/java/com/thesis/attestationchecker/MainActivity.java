package com.thesis.attestationchecker;

import android.os.Build;
import android.os.Bundle;

import androidx.activity.EdgeToEdge;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import android.util.Log;

public class MainActivity extends AppCompatActivity {

    private TextView textView;
    private TextView textView3;
    private final ExecutorService execService = Executors.newSingleThreadExecutor();

    @Override
    @RequiresApi(api = Build.VERSION_CODES.S)
    protected void onCreate(Bundle savedInstanceState) {
        //Default init
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        // Find objects
        textView = findViewById(R.id.textView);
        textView3 = findViewById(R.id.textView3);
        Button button = findViewById(R.id.button);

        //Set event listener
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                attest();
            }});
        }

    //Perform the attestation
    public void attest() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            //Try for ID attestation if API version allows it
            try {
                KeyGenParameterSpec paramsSign = buildKeyGenParameterSpec(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S);
                keyPairGenerator.initialize(paramsSign);
                keyPairGenerator.generateKeyPair();

            //Try without it if ID attestation wasn't implemented by devs
            } catch (java.security.ProviderException e) {
                textView3.setText("ID attestation failed... ): \nDevs were lazy on this one");
                KeyGenParameterSpec paramsSign = buildKeyGenParameterSpec(false);
                keyPairGenerator.initialize(paramsSign);
                keyPairGenerator.generateKeyPair();
            }
            processCertificateChain();

        //Something went seriously wrong
        } catch (Exception oops) {
            Log.d("Attestation", "Attestation Failed", oops);
            textView.setText("Whole attestation failed ):");
        }
    }

    private KeyGenParameterSpec buildKeyGenParameterSpec(boolean includeIDAttest) {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                "cool_alias", KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge("challenging_challenge".getBytes());

        // Only enable ID attestation if supported & desired
        if (includeIDAttest && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setDevicePropertiesAttestationIncluded(true);
        }

        return builder.build();
    }

    private void processCertificateChain() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        Certificate[] certChain = keyStore.getCertificateChain("cool_alias");

        //Get the leaf certificate & display basic data to verify everything works
        if (certChain != null && certChain.length > 0) {
            X509Certificate attestationCert = (X509Certificate) certChain[0];
            String certInfo =
                    "Certificate Subject: " + attestationCert.getSubjectDN().toString() + "\n\n" +
                    "Certificate Issuer: " + attestationCert.getIssuerDN().toString() + "\n\n" +
                    "Certificate Signature Algorithm: " + attestationCert.getSigAlgName() + "\n\n" +
                    "Certificate Public Key: " + Base64.encodeToString(attestationCert.getPublicKey().getEncoded(), Base64.DEFAULT);
            textView.setText(certInfo);

            //Send certificate to server in DER format
            sendCertificateToServer(Base64.encodeToString(attestationCert.getEncoded(), Base64.NO_WRAP));
        } else {
            textView.setText("The key was attested, but no certificate extracted ):");
        }
    }

    private void sendCertificateToServer(String certBase64) {
        execService.execute(() -> {
            try {
                URL url = new URL("http://89.58.61.25:4000");
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setDoOutput(true);

                String jsonPayload = "{\"certificate\": \"" + certBase64 + "\", \"model\": \"" + Build.MODEL + "\"}";
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(jsonPayload.getBytes());
                    os.flush();
                }


                int responseCode = connection.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    runOnUiThread(() -> textView.setText("Certificate sent successfully!"));
                } else {
                    runOnUiThread(() -> textView.setText("Failed to send certificate. Response code: " + responseCode
                            + "\n\nCertificate in Base 64: " + certBase64));
                }
            } catch (Exception e) {
                runOnUiThread(() -> textView.setText("Error: " + e.getMessage()));
            }
        });
    }
}