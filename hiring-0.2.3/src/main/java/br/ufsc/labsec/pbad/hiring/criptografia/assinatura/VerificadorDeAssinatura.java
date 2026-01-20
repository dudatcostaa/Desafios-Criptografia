package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por verificar a integridade de uma assinatura.
 */
public class VerificadorDeAssinatura {

    /**
     * Verifica a integridade de uma assinatura digital no padrão CMS.
     *
     * @param certificado certificado do assinante.
     * @param assinatura  documento assinado.
     * @return {@code true} se a assinatura for íntegra, e {@code false} do
     * contrário.
     * Algoritmo:
     * 1 - colocar as informações da assinatura em um SignerInformation
     * 2 - gerar um verificador de informações do certificado com SignerInformationVerifier
     * 3 - usar verify()
     */
    public boolean verificarAssinatura(X509Certificate certificado,
                                       CMSSignedData assinatura) {
        try {
            //https://stackoverflow.com/questions/56614572/what-exactly-does-signer-verifysignerinformationverifier-verify
            SignerInformation signer = this.pegaInformacoesAssinatura(assinatura);
            SignerInformationVerifier signerInformationVerifier = this.geraVerificadorInformacoesAssinatura(certificado);
            return signer.verify(signerInformationVerifier);
        } catch (CMSException | OperatorCreationException e){
            e.printStackTrace();
            return false;
        }

    }

    /**
     * Gera o verificador de assinaturas a partir das informações do assinante.
     *
     * @param certificado certificado do assinante.
     * @return Objeto que representa o verificador de assinaturas.
     * Algoritmo:
     * 1 - criar um construtor de verificador de assinatura
     * 2 - provedor como bouncycastle
     * 3 - gerar o verificador com o certificado recebido e retorná-lo
     */
    private SignerInformationVerifier geraVerificadorInformacoesAssinatura(X509Certificate certificado) throws OperatorCreationException {
        JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder(); //https://downloads.bouncycastle.org/java/docs/bcpkix-jdk14-javadoc/org/bouncycastle/cms/jcajce/JcaSimpleSignerInfoVerifierBuilder.html
        builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return builder.build(certificado);
    }

    /**
     * responsável por pegar as informações da assinatura dentro do CMS.
     *
     * @param assinatura documento assinado.
     * @return Informações da assinatura.
     * Algoritmo:
     * 1 - obter as informações do assinante com getSignerInfos()
     * 2 - obter o assinante getSigners(), .iterator().next() pega só o primeiro assinante
     * 3 - retornar um SignerInformation
     */
    private SignerInformation pegaInformacoesAssinatura(CMSSignedData assinatura) {
        return (SignerInformation) assinatura.getSignerInfos().getSigners().iterator().next(); //https://javadoc.io/doc/org.bouncycastle/bcmail-jdk15+/latest/org/bouncycastle/cms/CMSSignedData.html
    }

}
