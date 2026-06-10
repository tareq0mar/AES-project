package pckg;

import java.security.SecureRandom;

import java.util.Arrays;
import java.util.Scanner;

public class CryptoModes {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] encryptECB(byte[] plaintext, AesCipher aes) {
        byte[] padded = zeroPad(plaintext, 16);
        byte[] out = new byte[padded.length];

        for (int i = 0; i < padded.length; i += 16) {
            byte[] block = Arrays.copyOfRange(padded, i, i + 16);
            byte[] encrypted = aes.encryptBlock(block);
            System.arraycopy(encrypted, 0, out, i, 16);
        }
        return out;
    }

    public static byte[] decryptECB(byte[] ciphertext, AesCipher aes) {
        if (ciphertext.length % 16 != 0) throw new IllegalArgumentException("Cipher length must be multiple of 16 for ECB.");
        byte[] out = new byte[ciphertext.length];

        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + 16);
            byte[] decrypted = aes.decryptBlock(block);
            System.arraycopy(decrypted, 0, out, i, 16);
        }
        return zeroUnpad(out, 16);
    }

    public static byte[] encryptCBC(byte[] plaintext, AesCipher aes, byte[] iv) {
        requireLength(iv, 16, "IV");
        byte[] padded = zeroPad(plaintext, 16);
        byte[] out = new byte[padded.length];

        byte[] previousCipher = Arrays.copyOf(iv, 16);

        for (int i = 0; i < padded.length; i += 16) {
            byte[] plainBlock = Arrays.copyOfRange(padded, i, i + 16);
            byte ptemp = plainBlock[1];
            if(i==1) {
            	
            }
            byte[] xored = xor16(plainBlock, previousCipher);
            byte[] cipherBlock = aes.encryptBlock(xored);

            System.arraycopy(cipherBlock, 0, out, i, 16);
            previousCipher = cipherBlock;
        }
        return out;
    }

    public static byte[] decryptCBC(byte[] ciphertext, AesCipher aes, byte[] iv) {
        requireLength(iv, 16, "IV");
        if (ciphertext.length % 16 != 0) throw new IllegalArgumentException("Cipher length must be multiple of 16 for CBC.");
        byte[] out = new byte[ciphertext.length];

        byte[] previousCipher = Arrays.copyOf(iv, 16);

        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] cipherBlock = Arrays.copyOfRange(ciphertext, i, i + 16);
            byte[] decrypted = aes.decryptBlock(cipherBlock);
            byte[] plainBlock = xor16(decrypted, previousCipher);

            System.arraycopy(plainBlock, 0, out, i, 16);
            previousCipher = cipherBlock;
        }
        return zeroUnpad(out, 16);
    }

    public static byte[] encryptCFB(byte[] plaintext, AesCipher aes, byte[] iv) {
        requireLength(iv, 16, "IV");
        byte[] out = new byte[plaintext.length];

        byte[] feedback = Arrays.copyOf(iv, 16);

        for (int offset = 0; offset < plaintext.length; offset += 16) {
            byte[] stream = aes.encryptBlock(feedback);
            int chunk = Math.min(16, plaintext.length - offset);

            byte[] newFeedback = Arrays.copyOf(feedback, 16);
            for (int j = 0; j < chunk; j++) {
                byte cipherByte = (byte) (plaintext[offset + j] ^ stream[j]);
                out[offset + j] = cipherByte;
                newFeedback[j] = cipherByte; 
            }
            feedback = newFeedback;
        }
        return out;
    }

    public static byte[] decryptCFB(byte[] ciphertext, AesCipher aes, byte[] iv) {
        requireLength(iv, 16, "IV");
        byte[] out = new byte[ciphertext.length];

        byte[] feedback = Arrays.copyOf(iv, 16);

        for (int offset = 0; offset < ciphertext.length; offset += 16) {
            byte[] stream = aes.encryptBlock(feedback);
            int chunk = Math.min(16, ciphertext.length - offset);

            byte[] newFeedback = Arrays.copyOf(feedback, 16);
            for (int j = 0; j < chunk; j++) {
                byte plainByte = (byte) (ciphertext[offset + j] ^ stream[j]);
                out[offset + j] = plainByte;
                newFeedback[j] = ciphertext[offset + j];
            }
            feedback = newFeedback;
        }
        return out;
    }

    public static byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        secureRandom.nextBytes(b);
        return b;
    }

    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte x : data) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    public static byte[] hexToBytesStrict(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("HEX length must be even.");
        byte[] out = new byte[hex.length() / 2];

        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid HEX character.");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static void requireLength(byte[] bytes, int expected, String name) {
        if (bytes == null) throw new IllegalArgumentException(name + " is not set.");
        if (bytes.length != expected) throw new IllegalArgumentException(name + " must be " + expected + " bytes.");
    }

    public static byte[] xor16(byte[] a, byte[] b) {
        requireLength(a, 16, "Block A");
        requireLength(b, 16, "Block B");
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    public static byte[] zeroPad(byte[] data, int blockSize) {
        int remainder = data.length % blockSize;
        if (remainder == 0) return data;
        int padLength = blockSize - remainder;
        return Arrays.copyOf(data, data.length + padLength);
    }

    public static byte[] zeroUnpad(byte[] data, int blockSize) {
        if (data.length == 0) return data;
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i + 1);
    }

    public static int readInt(Scanner scanner, String prompt) {
        while (true) {
            System.out.print(prompt);
            String s = scanner.nextLine().trim();
            try { return Integer.parseInt(s); }
            catch (Exception e) { System.out.println("Please enter a valid number."); }
        }
    }

    public static String readLine(Scanner scanner, String prompt) {
        System.out.print(prompt);
        return scanner.nextLine();
    }
}