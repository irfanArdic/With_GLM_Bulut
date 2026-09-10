// kapibus.js
const Kapibus = {
    async sha256(buffer) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        return new Uint8Array(hashBuffer);
    },
    strToBytes(str) { return new TextEncoder().encode(str); },
    bytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); },
    
    async generateDIDBase(link, deviceID) {
        const data = new Uint8Array(link.length + deviceID.length);
        data.set(this.strToBytes(link), 0);
        data.set(this.strToBytes(deviceID), link.length);
        const hash = await this.sha256(data);
        return hash.slice(0, 8); // 64 Bit (8 Byte)
    },

    async generateMAC(didBase, data, macLen) {
        const combined = new Uint8Array(didBase.length + data.length);
        combined.set(didBase, 0);
        combined.set(data, didBase.length);
        const hash = await this.sha256(combined);
        return hash.slice(0, macLen);
    },

    // Adım 1: Challenge İsteği (Telefon -> ESP) - 8 Byte
    async buildChallengeRequest(slot, didBase) {
        const payload = new Uint8Array(2);
        payload[0] = slot & 0x7F; // 7 bit slot
        payload[1] = 0x01;        // Komut: Challenge Request
        const mac = await this.generateMAC(didBase, payload, 6);
        
        const packet = new Uint8Array(8);
        packet.set(payload, 0);
        packet.set(mac, 2);
        return packet;
    },

    // Adım 3: Kapı Açma Kanıtı (Telefon -> ESP) - 16 Byte
    async buildOpenProof(slot, seed, didBase, ntpTime, cmd = 0x03) {
        // 1. Açık Veri (10 Byte): NTP(4) + Slot(2) + Cmd(1) + Pad(3)
        const payload = new Uint8Array(10);
        const dv = new DataView(payload.buffer);
        dv.setUint32(0, ntpTime); // 32 Bit NTP (Big Endian)
        dv.setUint16(4, slot);    // 16 Bit Slot
        payload[6] = cmd;

        // 2. Keystream Üret: SHA256(Seed + DID_Base)
        const keyData = new Uint8Array(seed.length + didBase.length);
        keyData.set(seed, 0);
        keyData.set(didBase, seed.length);
        const keystream = (await this.sha256(keyData)).slice(0, 10);

        // 3. Şifrele (XOR)
        const encrypted = new Uint8Array(10);
        for (let i = 0; i < 10; i++) encrypted[i] = payload[i] ^ keystream[i];

        // 4. MAC Üret: SHA256(DID_Base + Encrypted)
        const mac = await this.generateMAC(didBase, encrypted, 6);

        // 5. Paketle (16 Byte)
        const packet = new Uint8Array(16);
        packet.set(encrypted, 0);
        packet.set(mac, 10);
        return packet;
    },

    // ESP'den gelen ACK paketini doğrula (8 Byte)
    async verifyAck(ackPacket, didBase) {
        const cmd = ackPacket[0];
        const receivedMac = ackPacket.slice(1, 8);
        const calculatedMac = await this.generateMAC(didBase, ackPacket.slice(0, 1), 7);
        
        let match = true;
        for (let i = 0; i < 7; i++) {
            if (calculatedMac[i] !== receivedMac[i]) { match = false; break; }
        }
        return match ? cmd : -1; // 0x04 (Açıldı) veya 0x05 (Reddedildi)
    },

    // 64 Byte Tam Kayıt Paketi Üretici (Kullanıcı -> ESP)
    async buildRegisterPacket(slot, didBase, blok, daire, kapi, rol, telStr, adStr, timestamp) {
        // 1. Payload (57 Byte)
        const payload = new Uint8Array(57);
        payload[0] = 0x80 | (slot & 0x7F); // Komut: Admin/Write + Slot
        payload[1] = 0x07;                   // Flags: FLAG_VALID(1) + FLAG_AKTIF(2) + FLAG_KAYITLI(4)
        payload[2] = blok & 0xFF;
        payload[3] = daire & 0xFF;
        payload[4] = ((rol & 0x03) << 6) | (((kapi - 1) & 0x03) << 4); // Rol ve Kapı aynı byte'da
        
        payload[5] = 0xFF; // Başlangıç Saati (Süresiz)
        payload[6] = 0xFF; // Bitiş Saati (Süresiz)
        
        // Telefon (14 Byte)
        const telBytes = this.strToBytes(telStr);
        payload.set(telBytes, 7);
        
        // İsim (24 Byte)
        const adBytes = this.strToBytes(adStr);
        payload.set(adBytes, 21);
        
        // DID_Base (8 Byte)
        payload.set(didBase, 45);
        
        // Timestamp (4 Byte)
        const dv = new DataView(payload.buffer);
        dv.setUint32(53, timestamp);

        // 2. MAC Üret (7 Byte): SHA256(DID_Base + Payload)
        const mac = await this.generateMAC(didBase, payload, 7);

        // 3. Paketi Birleştir (64 Byte)
        const packet = new Uint8Array(64);
        packet.set(payload, 0);
        packet.set(mac, 57);
        return packet;
    }
};
