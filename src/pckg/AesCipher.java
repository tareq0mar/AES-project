package pckg;

public class AesCipher {

    private final int rounds;          
    private final byte[][] roundKeys;
    
    private boolean verbose = false;

    public AesCipher(byte[] key) {
        if (key.length == 16) this.rounds = 10;
        else if (key.length == 24) this.rounds = 12;
        else throw new IllegalArgumentException("Key must be 16 bytes (AES-128) or 24 bytes (AES-192).");

        this.roundKeys = expandKey(key, 12);
    }
    
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public byte[][] getRoundKeys() {
        return roundKeys;
    }

    public byte[] encryptBlock(byte[] block16) {
        if (block16.length != 16) throw new IllegalArgumentException("AES block must be 16 bytes.");
        
        if (verbose) System.out.println("\n>>> START ENCRYPT BLOCK <<<");

        byte[][] state = blockToState(block16);
        if (verbose) printState("Input State", state);

        addRoundKey(state, roundKeys[0]);
        if (verbose) printState("Round 0 (AddRoundKey)", state);

        for (int round = 1; round <= rounds - 1; round++) {
            if (verbose) System.out.println("--- Round " + round + " ---");
            
            subBytes(state);
            if (verbose) printState("After SubBytes", state);
            
            shiftRows(state);
            if (verbose) printState("After ShiftRows", state);
            
            mixColumns(state);
            if (verbose) printState("After MixColumns", state);
            
            addRoundKey(state, roundKeys[round]);
            if (verbose) printState("After AddRoundKey", state);
        }

        if (verbose) System.out.println("--- Round " + rounds + " (Final) ---");
        
        subBytes(state);
        if (verbose) printState("After SubBytes", state);
        
        shiftRows(state);
        if (verbose) printState("After ShiftRows", state);
        
        addRoundKey(state, roundKeys[rounds]);
        if (verbose) printState("After AddRoundKey (Cipher)", state);

        return stateToBlock(state);
    }

    public byte[] decryptBlock(byte[] block16) {
        if (block16.length != 16) throw new IllegalArgumentException("AES block must be 16 bytes.");
        
        if (verbose) System.out.println("\n>>> START DECRYPT BLOCK <<<");

        byte[][] state = blockToState(block16);
        if (verbose) printState("Input Cipher State", state);

        addRoundKey(state, roundKeys[rounds]);
        if (verbose) printState("Round 0 (AddRoundKey)", state);

        for (int round = rounds - 1; round >= 1; round--) {
            if (verbose) System.out.println("--- Round " + (rounds - round) + " (Inv) ---");

            invShiftRows(state);
            if (verbose) printState("After InvShiftRows", state);
            
            invSubBytes(state);
            if (verbose) printState("After InvSubBytes", state);
            
            addRoundKey(state, roundKeys[round]);
            if (verbose) printState("After AddRoundKey", state);
            
            invMixColumns(state);
            if (verbose) printState("After InvMixColumns", state);
        }

        if (verbose) System.out.println("--- Round " + rounds + " (Final Inv) ---");

        invShiftRows(state);
        if (verbose) printState("After InvShiftRows", state);
        
        invSubBytes(state);
        if (verbose) printState("After InvSubBytes", state);
        
        addRoundKey(state, roundKeys[0]);
        if (verbose) printState("After AddRoundKey (Plain)", state);

        return stateToBlock(state);
    }

    private void printState(String label, byte[][] state) {
        System.out.println("   [ " + label + " ]");
        for (int r = 0; r < 4; r++) {
            System.out.print("     "); 
            for (int c = 0; c < 4; c++) {
                System.out.printf("%02X ", state[r][c]);
            }
            System.out.println();
        }
        System.out.println();
    }

    private static byte[][] expandKey(byte[] key, int rounds) {
      //  int nk = (key.length / 4);           
    	int nk =6;
        int totalWords = 4 * (rounds + 1);   
        int[] words = new int[totalWords];

        for (int i = 0; i < nk; i++) {
            words[i] = ((key[4*i] & 0xFF) << 24)
                    | ((key[4*i + 1] & 0xFF) << 16)
                    | ((key[4*i + 2] & 0xFF) << 8)
                    | (key[4*i + 3] & 0xFF);
        }

        for (int i = nk; i < totalWords; i++) {
            int temp = words[i - 1];
            if (i % nk == 0) {
                temp = subWord(rotWord(temp)) ^ (RCON[(i / nk) - 1] << 24);
            }
            words[i] = words[i - nk] ^ temp;
        }

        byte[][] keys = new byte[rounds + 1][16];
        for (int round = 0; round <= rounds; round++) {
            for (int col = 0; col < 4; col++) {
                int w = words[round * 4 + col];
                keys[round][4*col]     = (byte) ((w >>> 24) & 0xFF);
                keys[round][4*col + 1] = (byte) ((w >>> 16) & 0xFF);
                keys[round][4*col + 2] = (byte) ((w >>> 8) & 0xFF);
                keys[round][4*col + 3] = (byte) (w & 0xFF);
            }
        }
        return keys;
    }

    private static int rotWord(int x) {
        return (x << 8) | ((x >>> 24) & 0xFF);
    }

    private static int subWord(int x) {
        int b0 = SBOX[(x >>> 24) & 0xFF];
        int b1 = SBOX[(x >>> 16) & 0xFF];
        int b2 = SBOX[(x >>> 8) & 0xFF];
        int b3 = SBOX[x & 0xFF];
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

  
    private static byte[][] blockToState(byte[] block16) {
        byte[][] state = new byte[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = block16[col * 4 + row];
            }
        }
        return state;
    }

    private static byte[] stateToBlock(byte[][] state) {
        byte[] out = new byte[16];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                out[col * 4 + row] = state[row][col];
            }
        }
        return out;
    }

    private static void addRoundKey(byte[][] state, byte[] roundKey16) {
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] ^= roundKey16[col * 4 + row];
            }
        }
    }

    private static void subBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = (byte) SBOX[state[r][c] & 0xFF];
    }

    private static void invSubBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = (byte) INV_SBOX[state[r][c] & 0xFF];
    }

    private static void shiftRows(byte[][] state) {
        for (int row = 1; row < 4; row++) {
            byte[] tmp = new byte[4];
            for (int col = 0; col < 4; col++) tmp[col] = state[row][(col + row) % 4];
            for (int col = 0; col < 4; col++) state[row][col] = tmp[col];
        }
    }

    private static void invShiftRows(byte[][] state) {
        for (int row = 1; row < 4; row++) {
            byte[] tmp = new byte[4];
            for (int col = 0; col < 4; col++) tmp[col] = state[row][(col - row + 4) % 4];
            for (int col = 0; col < 4; col++) state[row][col] = tmp[col];
        }
    }

    private static void mixColumns(byte[][] state) {
        for (int col = 0; col < 4; col++) {
            int a0 = state[0][col] & 0xFF;
            int a1 = state[1][col] & 0xFF;
            int a2 = state[2][col] & 0xFF;
            int a3 = state[3][col] & 0xFF;

            state[0][col] = (byte) (mul(a0,2) ^ mul(a1,3) ^ mul(a2,1) ^ mul(a3,1));
            state[1][col] = (byte) (mul(a0,1) ^ mul(a1,2) ^ mul(a2,3) ^ mul(a3,1));
            state[2][col] = (byte) (mul(a0,1) ^ mul(a1,1) ^ mul(a2,2) ^ mul(a3,3));
            state[3][col] = (byte) (mul(a0,3) ^ mul(a1,1) ^ mul(a2,1) ^ mul(a3,2));
        }
    }

    private static void invMixColumns(byte[][] state) {
        for (int col = 0; col < 4; col++) {
            int a0 = state[0][col] & 0xFF;
            int a1 = state[1][col] & 0xFF;
            int a2 = state[2][col] & 0xFF;
            int a3 = state[3][col] & 0xFF;

            state[0][col] = (byte) (mul(a0,14) ^ mul(a1,11) ^ mul(a2,13) ^ mul(a3,9));
            state[1][col] = (byte) (mul(a0,9)  ^ mul(a1,14) ^ mul(a2,11) ^ mul(a3,13));
            state[2][col] = (byte) (mul(a0,13) ^ mul(a1,9)  ^ mul(a2,14) ^ mul(a3,11));
            state[3][col] = (byte) (mul(a0,11) ^ mul(a1,13) ^ mul(a2,9)  ^ mul(a3,14));
        }
    }


    private static int xtime(int a) {
        a <<= 1;
        if ((a & 0x100) != 0) a ^= 0x11B;
        return a & 0xFF;
    }

    private static int mul(int a, int b) {
        int result = 0;
        int x = a & 0xFF;
        int y = b;

        while (y > 0) {
            if ((y & 1) != 0) result ^= x;
            x = xtime(x);
            y >>= 1;
        }
        return result & 0xFF;
    }

    private static final int[] RCON = {
            0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A
    };

    private static final int[] SBOX = {
    	    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
    	    202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
    	    183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
    	    4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
    	    9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
    	    83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
    	    208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
    	    81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
    	    205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
    	    96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
    	    224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
    	    231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
    	    186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
    	    112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
    	    225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
    	    140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
    	};


    private static final int[] INV_SBOX = {
    	    82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,
    	    124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,
    	    84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,
    	    8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,
    	    114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,
    	    108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,
    	    144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,
    	    208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,
    	    58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,
    	    150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,
    	    71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,
    	    252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,
    	    31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,
    	    96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,
    	    160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,
    	    23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125
    	};

}