/**
 * Implementation of the LetterSoup AEAD-mode.
 * 
 * This implementation is tightly coupled with Marvin's (MAC). Though the AEAD
 * interface may suggest otherwise, LetterSoup's design requires Marvin to be
 * the used MAC. Behaviour is unknown should another MAC be set on this
 * implementation.
 * 
 * As with Marvin, the current implementation of LetterSoup suports only ciphers
 * that work with 96-bit blocks.
 */

public class LetterSoup implements AEAD {

    private MAC mac;
    private BlockCipher cipher;
    private int blockBytes;
    private int mLength;
    private int hLength;
    private int ivLength;
    private byte[] iv;
    private byte[] A;
    private byte[] D;
    private byte[] R;
    private byte[] L;

    public void setMAC(MAC mac) {
	this.mac = mac;
    }

    public void setCipher(BlockCipher cipher) {
	this.cipher = cipher;
	blockBytes = cipher.blockBits() / 8;
    }

    public void setKey(byte[] cipherKey, int keyBits) {
	cipher.makeKey(cipherKey, keyBits);
    }

    public void setIV(byte[] iv, int ivLength) {
	System.arraycopy(iv, 0, this.iv, 0, ivLength);
	this.ivLength = ivLength;
	R = null;
	L = null;
    }

    public void update(byte[] aData, int aLength) {
	L = new byte[blockBytes];
	D = new byte[blockBytes];
	hLength = aLength;

	cipher.encrypt(new byte[blockBytes], L);
	mac.init(L);
	mac.update(aData, aLength);
	mac.getTag(D, cipher.blockBits());
    }

    public byte[] encrypt(byte[] mData, int mLength, byte[] cData) {
	R = new byte[blockBytes];
	A = new byte[blockBytes];
	this.mLength = mLength;

	byte[] leftPaddedN = new byte[blockBytes];
	System.arraycopy(iv, 0, leftPaddedN, blockBytes - ivLength, blockBytes);
	cipher.encrypt(leftPaddedN, R);
	xor(R, leftPaddedN, blockBytes);

	if (cData == null)
	    cData = new byte[mLength];
	LFRSC(mData, mLength, cData);

	mac.init(R);
	mac.update(cData, mLength);
	mac.getTag(A, cipher.blockBits());

	return cData;
    }

    public byte[] decrypt(byte[] cData, int cLength, byte[] mData) {
	if (mData == null)
	    mData = new byte[cLength];
	LFRSC(cData, cLength, mData);
	return mData;
    }

    public byte[] getTag(byte[] tag, int tagBits) {
	if (tag == null)
	    tag = new byte[tagBits / 8];

	byte[] aux1 = new byte[blockBytes];
	aux1[0] = (byte) (cipher.blockBits() - tagBits);
	aux1[1] = (byte) 0x80;
	byte[] aux2 = new byte[blockBytes];
	for (int i = 0; i < 4; ++i)
	    aux2[blockBytes - i - 1] = (byte) (mLength >>> (8 * i));
	xor(A, R, blockBytes);
	xor(A, aux1, blockBytes);
	xor(A, aux2, blockBytes);

	if (L != null) {
	    aux2 = new byte[blockBytes];
	    for (int i = 0; i < 4; ++i)
		aux2[blockBytes - i - 1] = (byte) (hLength >>> (8 * i));
	    xor(D, L, blockBytes);
	    xor(D, aux1, blockBytes);
	    xor(D, aux2, blockBytes);
	    cipher.sct(D, aux1);
	    xor(A, aux1, blockBytes);
	}

	cipher.encrypt(A, aux1);
	for (int i = blockBytes - tagBits / 8, j = 0; i < blockBytes; ++i, ++j)
	    tag[j] = aux1[i];

	return tag;
    }

    private void xor(byte[] a, byte[] b, int size) {
	for (int i = 0; i < size; ++i)
	    a[i] = (byte) (a[i] ^ b[i]);
    }

    private void LFRSC(byte[] mData, int mLength, byte[] cData) {
	byte[] M = new byte[blockBytes];
	byte[] C = new byte[blockBytes];
	byte[] O = new byte[blockBytes];

	System.arraycopy(R, 0, O, 0, blockBytes);
	int q = mLength / blockBytes;
	int r = mLength % blockBytes;

	for (int i = 0; i < q; ++i) {
	    System.arraycopy(mData, i * blockBytes, M, 0, blockBytes);
	    updateOffset(O);
	    cipher.encrypt(O, C);
	    xor(C, M, blockBytes);
	    System.arraycopy(C, 0, cData, i * blockBytes, blockBytes);
	}
	if (r != 0) {
	    System.arraycopy(mData, (q + 1) * blockBytes, M, 0, r);
	    updateOffset(O);
	    cipher.encrypt(O, C);
	    xor(C, M, blockBytes);
	    cipher.sct(M, A);
	    System.arraycopy(C, 0, cData, (q + 1) * blockBytes, r);
	}
    }

    private void updateOffset(byte[] O) {
	byte O0 = O[0];
	System.arraycopy(O, 1, O, 0, 11);
	O[9] = (byte) (O[9] ^ O0 ^ (O0 >>> 3) ^ (O0 >>> 5));
	O[10] = (byte) (O[10] ^ (O0 << 5) ^ (O0 << 3));
	O[11] = O0;
    }
}
