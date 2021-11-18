var escapehtml = require('escape-html');

module.exports = ({ publicKey, encryptedKey, algorithmID, PartyUInfo, PartyVInfo }) => `
<ds:KeyInfo>
  <xenc:EncryptedKey Id="_8a78f65e15098963ada9a43a4293fae6">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
      <ds:KeyInfo>
        <xenc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
          <xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
            <xenc11:ConcatKDFParams AlgorithmID="${algorithmID}" PartyUInfo="${PartyUInfo}" PartyVInfo="${PartyVInfo}">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            </xenc11:ConcatKDFParams>
          </xenc11:KeyDerivationMethod>
			<xenc:OriginatorKeyInfo>
              <ds:KeyValue>
                <dsig11:ECKeyValue>
                  <dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>
                  <dsig11:PublicKey>${escapehtml(publicKey)}</dsig11:PublicKey>
                </dsig11:ECKeyValue>
              </ds:KeyValue>
            </xenc:OriginatorKeyInfo>
        </xenc:AgreementMethod>
      </ds:KeyInfo>
    <xenc:CipherData>
      <xenc:CipherValue>${escapehtml(encryptedKey)}</xenc:CipherValue>
    </xenc:CipherData>
  </xenc:EncryptedKey>
</ds:KeyInfo>
`;