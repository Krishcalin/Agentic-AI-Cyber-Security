// Deliberately vulnerable Java code for testing
import java.sql.*;
import java.io.*;
import java.security.*;

public class VulnerableApp {
    // SQL Injection
    public void getUser(String name) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    // Command Injection
    public void runCmd(String input) throws Exception {
        Runtime.getRuntime().exec(input);
    }

    // Weak Hash
    public String hashPassword(String pw) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(pw.getBytes()));
    }

    // Weak Cipher
    public void encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    // Deserialization
    public Object loadObject(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }

    // Hardcoded Password
    String password = "SuperSecret123!";
    String dbUrl = "jdbc:mysql://localhost/db";

    // SSL Disabled
    // TrustAllCerts implementation
    public void trustAll() {
        // ALLOW_ALL_HOSTNAME_VERIFIER usage
    }

    // XSS
    public void echo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.getWriter().write(request.getParameter("input"));
    }

    // Insecure Random
    java.util.Random rand = new java.util.Random();

    // CSRF Disabled
    // http.csrf().disable()
}
