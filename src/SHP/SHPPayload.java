package SHP;

import java.io.Serializable;

/**
 * SHPPayload
 */
public class SHPPayload implements Serializable {
    public static class Type1 extends SHPPayload {
        public byte[] userId;

        public Type1(byte[] data) { this.userId = data; }

        public String getUserId() {
            return new String(userId, 0, userId.length).trim();
        }

        @Override
        public String toString() {
            return "Payload [userId = " + getUserId() + "]";
        }
    }

    public static class Type2 extends SHPPayload {
        public byte[] salt;
        public byte[] counter;
        public byte[] chall;

        public Type2(byte[] salt, byte[] counter, byte[] chall) {
            this.salt = salt;
            this.counter = counter;
            this.chall = chall;
        }

        @Override
        public String toString() {
            return "Payload [salt = " + Utils.bytesToHex(salt) +
                ", counter = " + Utils.bytesToHex(counter) +
                ", chall = " + Utils.bytesToHex(chall) + "]";
        }
    }

    public static class Type3 extends SHPPayload {
        public byte[] pbe;
        public byte[] ydhClient;
        public byte[] signature;
        public byte[] authCode;

        public Type3(byte[] pbe, byte[] ydhClient, byte[] signature,
                     byte[] authCode) {
            this.pbe = pbe;
            this.ydhClient = ydhClient;
            this.signature = signature;
            this.authCode = authCode;
        }

        @Override
        public String toString() {
            return "Payload [pbe = " + Utils.bytesToHex(pbe) +
                ", ydhClient = " + Utils.bytesToHex(ydhClient) +
                ", signature = " + Utils.bytesToHex(signature) +
                ", authCode = " + Utils.bytesToHex(authCode) + "]";
        }
    }

    public static class Type4 extends SHPPayload {
        public byte[] envelope;
        public byte[] ydhServer;
        public byte[] signature;
        public byte[] authCode;

        public Type4(byte[] envelope, byte[] ydhServer, byte[] signature,
                     byte[] authCode) {
            this.envelope = envelope;
            this.ydhServer = ydhServer;
            this.signature = signature;
            this.authCode = authCode;
        }

        @Override
        public String toString() {
            return "Payload [envelope = " + Utils.bytesToHex(envelope) +
                ", ydhServer = " + Utils.bytesToHex(ydhServer) +
                ", signature = " + Utils.bytesToHex(signature) +
                ", authCode = " + Utils.bytesToHex(authCode) + "]";
        }
    }
}
