package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import br.ufsc.labsec.pbad.hiring.Constantes;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por gerar uma assinatura digital.
 * <p>
 * Aqui será necessário usar a biblioteca Bouncy Castle, pois ela já possui a
 * estrutura básica da assinatura implementada.
 */
public class GeradorDeAssinatura {

    private X509Certificate certificado;
    private PrivateKey chavePrivada;
    private CMSSignedDataGenerator geradorAssinaturaCms;

    /**
     * Construtor.
     */
    public GeradorDeAssinatura() {
        this.geradorAssinaturaCms = new CMSSignedDataGenerator();
    }

    /**
     * Informa qual será o assinante.
     *
     * @param certificado  certificado, no padrão X.509, do assinante.
     * @param chavePrivada chave privada do assinante.
     */
    public void informaAssinante(X509Certificate certificado,
                                 PrivateKey chavePrivada) {
        this.certificado = certificado;
        this.chavePrivada = chavePrivada;
    }

    /**
     * Gera uma assinatura no padrão CMS.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento assinado.
     *
     * Algoritmo:
     * 1 - preparar os dados para a assinatura
     * 2 - gerar as informações do assinante
     * 3 - adicionar o certificado à assinatura
     * 4 - retorna CMSSignedData
     *
     */

    //https://www.javatips.net/api/org.bouncycastle.cms.cmssigneddata
    //https://downloads.bouncycastle.org/java/docs/bcpkix-jdk13-javadoc/org/bouncycastle/cms/CMSSignedDataGenerator.html para checar os métodos
    public CMSSignedData assinar(String caminhoDocumento) {

        try {
            CMSTypedData msg = this.preparaDadosParaAssinar(caminhoDocumento); //1

            SignerInfoGenerator infoAss = preparaInformacoesAssinante(chavePrivada, certificado); //2
            geradorAssinaturaCms.addSignerInfoGenerator(infoAss);

            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificado.getEncoded()); //3
            geradorAssinaturaCms.addCertificate(certificateHolder);

            return geradorAssinaturaCms.generate(msg, true); //4

        } catch (IOException | CertificateEncodingException | CMSException e){
            System.err.println("Erro ao assinar certificado");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Transforma o documento que será assinado para um formato compatível
     * com a assinatura.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento no formato correto.
     *
     * Algoritmo:
     * 1 - ler os bytes do arquivo do caminho
     * 2 - criar um CMSProcessableByteArray para retornar os dados
     */
    //https://downloads.bouncycastle.org/java/docs/bcpkix-jdk18on-javadoc/org/bouncycastle/cms/CMSTypedData.html
    //https://downloads.bouncycastle.org/java/docs/bcpkix-jdk18on-javadoc/org/bouncycastle/cms/CMSProcessableByteArray.html
    private CMSTypedData preparaDadosParaAssinar(String caminhoDocumento) {
        try{
            byte[] dados = Files.readAllBytes(Paths.get(caminhoDocumento));
            return new CMSProcessableByteArray(dados); //CMSProcessableByteArray implementa CMSTypedData
        } catch (IOException e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Gera as informações do assinante na estrutura necessária para ser
     * adicionada na assinatura.
     *
     * @param chavePrivada chave privada do assinante.
     * @param certificado  certificado do assinante.
     * @return Estrutura com informações do assinante.
     *
     * Algoritmo:
     * 1 - inicializar o builder JcaSimpleSignerInfoGeneratorBuilder
     * 2 - construir o SignerInfoGenerator para retorná-lo
     */
    private SignerInfoGenerator preparaInformacoesAssinante(PrivateKey chavePrivada,
                                                            Certificate certificado) {
        try {
            JcaSimpleSignerInfoGeneratorBuilder jcaSimpleSignerInfoGeneratorBuilder = new JcaSimpleSignerInfoGeneratorBuilder(); //https://downloads.bouncycastle.org/java/docs/bcpkix-jdk13-javadoc/org/bouncycastle/cms/jcajce/JcaSimpleSignerInfoGeneratorBuilder.html
            SignerInfoGenerator signerInfoGenerator = jcaSimpleSignerInfoGeneratorBuilder.build(Constantes.algoritmoAssinatura, chavePrivada, (X509Certificate) certificado); //https://javadoc.io/doc/org.bouncycastle/bcpkix-jdk15on/latest/org/bouncycastle/cms/SignerInfoGenerator.html
            return signerInfoGenerator;
        }catch (OperatorCreationException | CertificateEncodingException e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Escreve a assinatura no local apontado.
     *
     * @param arquivo    arquivo que será escrita a assinatura.
     * @param assinatura objeto da assinatura.
     * Algoritmo:
     * 1 - codificar a assinatura digital no formato binário DER
     * 2 - write()
     */
    public void escreveAssinatura(OutputStream arquivo, CMSSignedData assinatura) {
        try {
            arquivo.write(assinatura.getEncoded(ASN1Encoding.DER));
            arquivo.close();
        } catch (IOException e){
            e.printStackTrace();
        }
    }

}
