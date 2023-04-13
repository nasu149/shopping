<%@ page language="java" contentType="text/html; charset=UTF-8" %>
<%@ page import="java.io.*, java.security.*, java.security.KeyStore.Entry, java.util.*, javax.crypto.*, javax.crypto.spec.*, org.picketbox.plugins.vault.SecurityVaultData, org.picketbox.util.*" %>
<%@ page import="java.lang.reflect.Method" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="ja" lang="ja">
<head>
<title>test\</title>
</head>
<body>
<div id="main">
<%
    //https://github.com/picketbox/picketbox/tree/master/security-spi/spi/src/main/java/org/jboss/security/vault
    //https://github.com/picketbox/bare-vault/blob/master/src/main/java/org/picketbox/util/EncryptionUtil.java
    //https://github.com/picketbox/bare-vault/blob/master/src/main/java/org/picketbox/plugins/vault/PicketBoxSecurityVault.java
    //https://github.com/picketbox/bare-vault/blob/master/src/main/java/org/picketbox/plugins/vault/SecurityVaultData.java
    FileInputStream fis = null;
    ObjectInputStream ois = null;
    SecurityVaultData svd = null;
    Map<String, byte[]> map = null;
   
    fis = new FileInputStream("./vault/VAULT.dat");
    ois = new ObjectInputStream(fis);
    svd = (SecurityVaultData) ois.readObject();
    // map = (Map<String, byte[]>) ois.readObject();
    //System.out.println(map); 
    System.out.println(svd);
    

    String alias = "vault";
    String vaultBlock = "vb";
    String attributeName = "password";

    Class clazz = svd.getClass();

    // メソッド(setStr)の取得
    String strMethod1 = "getVaultData";
    Method m = clazz.getDeclaredMethod(strMethod1, String.class,String.class,String.class);
    // メソッド(setStr)の実行
    m.setAccessible(true);
    byte[] encryptedValue = (byte[])m.invoke(svd, alias, vaultBlock, attributeName);
    // byte[] encryptedValue = svd.getVaultData(alias, vaultBlock, attributeName);

    // out.println(encryptedValue);

    char[] keypass = "vault22".toCharArray();

    String keyStoreType = "JCEKS";
    String keystoreURL = "./vault/vault.keystore";
    KeyStore keystore = KeyStoreUtil.getKeyStore(keyStoreType, keystoreURL, keypass);

    Entry e = keystore.getEntry(alias, new KeyStore.PasswordProtection(keypass));
    SecretKey adminKey = ((KeyStore.SecretKeyEntry)e).getSecretKey();
    
    String encryptionAlgorithm = "AES";

    SecretKeySpec secretKeySpec = new SecretKeySpec(adminKey.getEncoded(), encryptionAlgorithm);

    int keySize = 128;
    EncryptionUtil encUtil = new EncryptionUtil(encryptionAlgorithm, keySize);

    out.println(new String(encUtil.decrypt(encryptedValue, secretKeySpec)));


%>
</div>
</body>
</html>