package com.ibm.as400.access;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

class SSLUtil {

    private static KeyStore loadKeyStore(String filePath, String password) throws Exception {
        if (filePath == null || filePath.isEmpty()) {
            return null;
        }
        String lowerPath = filePath.toLowerCase();

        if (lowerPath.endsWith(".crt") || lowerPath.endsWith(".cer") || lowerPath.endsWith(".pem")) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            try (FileInputStream fis = new FileInputStream(filePath)) {
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                java.util.Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(fis);
                int i = 0;
                for (java.security.cert.Certificate cert : certs) {
                    ks.setCertificateEntry("cert" + (i++), cert);
                }
            }
            return ks;
        }

        String type = "JKS";
        if (lowerPath.endsWith(".p12") || lowerPath.endsWith(".pfx")) {
            type = "PKCS12";
        }
        KeyStore ks = KeyStore.getInstance(type);
        try (FileInputStream fis = new FileInputStream(filePath)) {
            char[] pass = (password != null && !password.isEmpty()) ? password.toCharArray() : null;
            ks.load(fis, pass);
        }
        return ks;
    }

    public static SSLSocketFactory getCustomSSLSocketFactory(final String truststoreFile, final String truststorePass, final String keystoreFile, final String keystorePass) {
        if ((null != truststoreFile && !truststoreFile.isEmpty()) || (null != keystoreFile && !keystoreFile.isEmpty())) {
            return new SSLSocketFactory() {
                private SSLSocketFactory sslSocketFactory_ = null;

                private synchronized SSLSocketFactory getSSLSocketFactory() throws IOException {
                    if (null != sslSocketFactory_) {
                        return sslSocketFactory_;
                    }
                    if ("*ANY".equalsIgnoreCase(truststoreFile) && "*ANY".equalsIgnoreCase(truststorePass)) {
                        try {
                            SSLContext ctx = SSLContext.getInstance("TLS");
                            ctx.init(null, new TrustManager[] {
                                    new X509TrustManager() {
                                        @Override  public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { }
                                        @Override  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { }
                                        @Override  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                                    }
                            }, null);
                            return sslSocketFactory_ = ctx.getSocketFactory();
                        } catch (Exception e) {
                            throw e instanceof IOException ? (IOException) e : new IOException(e);
                        }
                    }
                    try {
                        KeyManager[] keyManagers = null;
                        TrustManager[] trustManagers = null;
                        SSLContext ctx = SSLContext.getInstance("TLS");

                        if (truststoreFile != null && !truststoreFile.isEmpty()) {
                            KeyStore myKeyStore = loadKeyStore(truststoreFile, truststorePass);
                            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                            trustManagerFactory.init(myKeyStore);
                            trustManagers = trustManagerFactory.getTrustManagers();
                        }

                        if (keystoreFile != null && !keystoreFile.isEmpty()) {
                            KeyStore myKeyStore = loadKeyStore(keystoreFile, keystorePass);
                            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                            char[] pass = (keystorePass != null && !keystorePass.isEmpty()) ? keystorePass.toCharArray() : new char[0];
                            keyManagerFactory.init(myKeyStore, pass);
                            keyManagers = keyManagerFactory.getKeyManagers();
                        }

                        ctx.init(keyManagers, trustManagers, null);
                        return sslSocketFactory_ = ctx.getSocketFactory();
                    } catch (Exception e) {
                        throw e instanceof IOException ? (IOException) e : new IOException(e);
                    }
                }

                @Override
                public String[] getDefaultCipherSuites() {
                    try { return getSSLSocketFactory().getDefaultCipherSuites();} catch (Exception e) { }
                    return ((SSLSocketFactory) SSLSocketFactory.getDefault()).getDefaultCipherSuites();
                }

                @Override
                public String[] getSupportedCipherSuites() {
                    try { return getSSLSocketFactory().getSupportedCipherSuites(); } catch (Exception e) { }
                    return ((SSLSocketFactory) SSLSocketFactory.getDefault()).getSupportedCipherSuites();
                }

                @Override
                public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose) throws IOException {
                    return getSSLSocketFactory().createSocket(s, host, port, autoClose);
                }

                @Override
                public java.net.Socket createSocket(String host, int port) throws IOException {
                    return getSSLSocketFactory().createSocket(host, port);
                }

                @Override
                public java.net.Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws IOException {
                    return getSSLSocketFactory().createSocket(host, port, localHost, localPort);
                }

                @Override
                public java.net.Socket createSocket(java.net.InetAddress host, int port) throws IOException {
                    return getSSLSocketFactory().createSocket(host, port);
                }

                @Override
                public java.net.Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws IOException {
                    return getSSLSocketFactory().createSocket(address, port, localAddress, localPort);
                }
            };
        }
        return null;
    }
}