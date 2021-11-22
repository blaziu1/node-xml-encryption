var escapehtml = require('escape-html');

module.exports = ({ publicKey, encryptedKey, algorithmID, PartyUInfo, PartyVInfo }) => `
<KeyInfo>
  <e:EncryptedKey Id="_8a78f65e15098963ada9a43a4293fae6">
    <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
      <KeyInfo>
        <e:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
          <xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
            <xenc11:ConcatKDFParams AlgorithmID="${algorithmID}" PartyUInfo="${PartyUInfo}" PartyVInfo="${PartyVInfo}">
              <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            </xenc11:ConcatKDFParams>
          </xenc11:KeyDerivationMethod>
			<e:OriginatorKeyInfo>
              <KeyValue>
                <dsig11:ECKeyValue>
                  <dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>
                  <dsig11:PublicKey>${escapehtml(publicKey)}</dsig11:PublicKey>
                </dsig11:ECKeyValue>
              </KeyValue>
            </e:OriginatorKeyInfo>
        </e:AgreementMethod>
      </KeyInfo>
    <e:CipherData>
      <e:CipherValue>${escapehtml(encryptedKey)}</e:CipherValue>
    </e:CipherData>
  </e:EncryptedKey>
</KeyInfo>
`;