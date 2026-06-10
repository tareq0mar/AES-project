package pckg;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class Main {
    private static final Scanner scanner = new Scanner(System.in);

    private static int aesKeyBits = 128;     
    private static String aesMode = "ECB";   

    private static byte[] secretKey = null; 
    private static byte[] iv = null;
    
    private static boolean visualize = false;

    public static void main(String[] args) {
        while (true) {
            printStatus();

            System.out.println("""
                    1) Choose AES Key Size (128 / 192)
                    2) Set Key (HEX / TEXT) or Generate Random
                    3) Expand Key and Display Round Keys
                    4) Choose Mode (ECB / CBC / CFB)
                    5) Set IV (HEX) or Generate Random (CBC/CFB only)
                    6) Encrypt (input TEXT or HEX)  -> output HEX
                    7) Decrypt (input HEX)          -> output TEXT or HEX
                    8) Exit
                    9) Toggle Visualization Mode
                    """);

            int choice = CryptoModes.readInt(scanner, "Choose: ");
            switch (choice) {
                case 1 -> chooseKeySize();
                case 2 -> setKey();
                case 3 -> showExpandedKeys();
                case 4 -> chooseMode();
                case 5 -> setIV();
                case 6 -> encrypt();
                case 7 -> decrypt();
                case 8 -> { System.out.println("Bye."); return; }
                case 9 -> toggleVisualization();
                default -> System.out.println("Invalid choice.");
            }
        }
    }

    private static void printStatus() {
        System.out.println("\n================ AES Project =================");
        System.out.println("AES Key Size  : " + aesKeyBits);
        System.out.println("Mode          : " + aesMode);
        System.out.println("Visualization : " + (visualize ? "ON (Verbose)" : "OFF")); 
        System.out.println("Key is set    : " + (secretKey != null));
        if (aesMode.equals("CBC") || aesMode.equals("CFB")) {
            System.out.println("IV is set     : " + (iv != null) + (iv != null ? (" | IV=" + CryptoModes.toHex(iv)) : ""));
        }
        System.out.println("=============================================\n");
    }

    private static void toggleVisualization() {
        visualize = !visualize;
        System.out.println("Visualization mode is now " + (visualize ? "ON" : "OFF") + ".");
    }

    private static void chooseKeySize() {
        int bits = CryptoModes.readInt(scanner, "Enter key size (128 or 192): ");
        if (bits != 128 && bits != 192) {
            System.out.println("Key size must be 128 or 192.");
            return;
        }
        aesKeyBits = bits;
        secretKey = null;
        System.out.println("Key size set to AES-" + aesKeyBits + ".");
    }

    private static void setKey() {
        int expectedBytes = aesKeyBits / 8;

        System.out.println("""
                Key option:
                1) HEX (Console)
                2) TEXT (Console - UTF-8)
                3) Generate random
                4) Read from File
                """);
        int option = CryptoModes.readInt(scanner, "Choose: ");

        try {
            byte[] key = null;

            if (option == 1) {
                String hex = CryptoModes.readLine(scanner, "Enter HEX key: ").trim();
                key = CryptoModes.hexToBytesStrict(hex);

            } else if (option == 2) {
                String text = CryptoModes.readLine(scanner, "Enter TEXT key: ");
                key = text.getBytes(StandardCharsets.UTF_8);

            } else if (option == 3) {
                key = CryptoModes.randomBytes(expectedBytes);
                System.out.println("Generated Key (HEX): " + CryptoModes.toHex(key));

            } else if (option == 4) {
                String path = CryptoModes.readLine(scanner, "Enter file path: ");
                System.out.println("Is the file content 1) HEX or 2) TEXT?");
                int type = CryptoModes.readInt(scanner, "Choose: ");
                String content = readFileAsString(path);

                if (type == 1) key = CryptoModes.hexToBytesStrict(content);
                else key = content.getBytes(StandardCharsets.UTF_8);

            } else {
                System.out.println("Invalid option.");
                return;
            }

            CryptoModes.requireLength(key, expectedBytes, "Key");
            secretKey = key;
            System.out.println("Key set successfully.");

        } catch (Exception ex) {
            System.out.println("Key error: " + ex.getMessage());
        }
    }

    private static void showExpandedKeys() {
        if (!ensureKey()) return;

        AesCipher aes = new AesCipher(secretKey);
        byte[][] roundKeys = aes.getRoundKeys();

        System.out.println("Round Keys:");
        for (int round = 0; round < roundKeys.length; round++) {
            System.out.println("Round " + round + ": " + CryptoModes.toHex(roundKeys[round]));
        }
    }

    private static void chooseMode() {
        String m = CryptoModes.readLine(scanner, "Mode (ECB/CBC/CFB): ").trim().toUpperCase();
        if (!m.equals("ECB") && !m.equals("CBC") && !m.equals("CFB")) {
            System.out.println("Invalid mode.");
            return;
        }
        aesMode = m;
        if (aesMode.equals("ECB")) iv = null;
    }

    private static void setIV() {
        if (!(aesMode.equals("CBC") || aesMode.equals("CFB"))) {
            System.out.println("IV is only used for CBC/CFB.");
            return;
        }

        System.out.println("""
                IV option:
                1) HEX (16 bytes)
                2) Generate random
                """);
        int option = CryptoModes.readInt(scanner, "Choose: ");

        try {
            if (option == 1) {
                String hex = CryptoModes.readLine(scanner, "Enter IV HEX (32 hex chars): ").trim();
                byte[] value = CryptoModes.hexToBytesStrict(hex);
                CryptoModes.requireLength(value, 16, "IV");
                iv = value;

            } else if (option == 2) {
                iv = CryptoModes.randomBytes(16);
                System.out.println("Generated IV (HEX): " + CryptoModes.toHex(iv));

            } else {
                System.out.println("Invalid option.");
            }
        } catch (Exception ex) {
            System.out.println("IV error: " + ex.getMessage());
        }
    }

    private static void encrypt() {
        if (!ensureKey()) return;
        if ((aesMode.equals("CBC") || aesMode.equals("CFB")) && iv == null) {
            System.out.println("Set IV first (option 5).");
            return;
        }

        try {
            System.out.println("\n--- Encryption Input ---");
            System.out.println("1) Console (TEXT)\n2) Console (HEX)\n3) File");
            int inChoice = CryptoModes.readInt(scanner, "Choose input source: ");

            byte[] plainBytes;

            if (inChoice == 1) {
                String text = CryptoModes.readLine(scanner, "Enter plaintext: ");
                plainBytes = text.getBytes(StandardCharsets.UTF_8);
            } else if (inChoice == 2) {
                String hex = CryptoModes.readLine(scanner, "Enter HEX: ");
                plainBytes = CryptoModes.hexToBytesStrict(hex);
            } else if (inChoice == 3) {
                String path = CryptoModes.readLine(scanner, "Enter input file path: ");
                System.out.println("Is file content 1) TEXT or 2) HEX?");
                int type = CryptoModes.readInt(scanner, "Choose: ");
                String content = readFileAsString(path);
                if (type == 2) plainBytes = CryptoModes.hexToBytesStrict(content);
                else plainBytes = content.getBytes(StandardCharsets.UTF_8);
            } else {
                System.out.println("Invalid input choice.");
                return;
            }

            AesCipher aes = new AesCipher(secretKey);
            aes.setVerbose(visualize); 
            
            byte[] cipherBytes = switch (aesMode) {
                case "ECB" -> CryptoModes.encryptECB(plainBytes, aes);
                case "CBC" -> CryptoModes.encryptCBC(plainBytes, aes, iv);
                case "CFB" -> CryptoModes.encryptCFB(plainBytes, aes, iv);
                default -> throw new IllegalStateException("Unexpected mode: " + aesMode);
            };

            String cipherHex = CryptoModes.toHex(cipherBytes);

            System.out.println("\n--- Encryption Output ---");
            System.out.println("1) Display to Console\n2) Save to File");
            int outChoice = CryptoModes.readInt(scanner, "Choose output dest: ");

            if (outChoice == 2) {
                String path = CryptoModes.readLine(scanner, "Enter output file path: ");
                writeStringToFile(path, cipherHex); 
            } else {
                System.out.println("Ciphertext (HEX): " + cipherHex);
            }

        } catch (Exception ex) {
            System.out.println("Encrypt error: " + ex.getMessage());
        }
    }
    
    private static void decrypt() {
        if (!ensureKey()) return;
        if ((aesMode.equals("CBC") || aesMode.equals("CFB")) && iv == null) {
            System.out.println("Set IV first (option 5).");
            return;
        }

        try {
            System.out.println("\n--- Decryption Input ---");
            System.out.println("1) Console (HEX)\n2) File (HEX content)");
            int inChoice = CryptoModes.readInt(scanner, "Choose input source: ");

            byte[] cipherBytes;
            if (inChoice == 1) {
                String hex = CryptoModes.readLine(scanner, "Enter ciphertext HEX: ").trim();
                cipherBytes = CryptoModes.hexToBytesStrict(hex);
            } else if (inChoice == 2) {
                String path = CryptoModes.readLine(scanner, "Enter input file path: ");
                String content = readFileAsString(path);
                cipherBytes = CryptoModes.hexToBytesStrict(content);
            } else {
                System.out.println("Invalid input choice.");
                return;
            }

            AesCipher aes = new AesCipher(secretKey);
            aes.setVerbose(visualize);

            byte[] plainBytes = switch (aesMode) {
                case "ECB" -> CryptoModes.decryptECB(cipherBytes, aes);
                case "CBC" -> CryptoModes.decryptCBC(cipherBytes, aes, iv);
                case "CFB" -> CryptoModes.decryptCFB(cipherBytes, aes, iv);
                default -> throw new IllegalStateException("Unexpected mode: " + aesMode);
            };

            System.out.println("\n--- Decryption Output ---");
            System.out.println("1) Text\n2) HEX");
            int format = CryptoModes.readInt(scanner, "Choose output format: ");
            
            String outputString;
            if (format == 1) outputString = new String(plainBytes, StandardCharsets.UTF_8);
            else outputString = CryptoModes.toHex(plainBytes);

            System.out.println("1) Display to Console\n2) Save to File");
            int outChoice = CryptoModes.readInt(scanner, "Choose output dest: ");

            if (outChoice == 2) {
                String path = CryptoModes.readLine(scanner, "Enter output file path: ");
                writeStringToFile(path, outputString);
            } else {
                System.out.println("Decrypted Result: " + outputString);
            }

        } catch (Exception ex) {
            System.out.println("Decrypt error: " + ex.getMessage());
        }
    }

    private static boolean ensureKey() {
        if (secretKey == null) {
            System.out.println("Please set the key first (option 2).");
            return false;
        }
        return true;
    }
 
    private static String readFileAsString(String filepath) throws java.io.IOException {
        byte[] encoded = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filepath));
        return new String(encoded, StandardCharsets.UTF_8).trim();
    }

    private static void writeStringToFile(String filepath, String data) throws java.io.IOException {
        java.nio.file.Files.write(java.nio.file.Paths.get(filepath), data.getBytes(StandardCharsets.UTF_8));
        System.out.println("Saved to file: " + filepath);
    }
}