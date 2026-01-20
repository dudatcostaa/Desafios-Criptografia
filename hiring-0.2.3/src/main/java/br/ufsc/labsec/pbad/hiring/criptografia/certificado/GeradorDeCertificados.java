package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import static br.ufsc.labsec.pbad.hiring.Constantes.algoritmoAssinatura;
import static br.ufsc.labsec.pbad.hiring.Constantes.formatoCertificado;

/**
 * Classe responsável por gerar certificados no padrão X.509.
 * <p>
 * Um certificado é basicamente composto por três partes, que são:
 * <ul>
 * <li>
 * Estrutura de informações do certificado;
 * </li>
 * <li>
 * Algoritmo de assinatura;
 * </li>
 * <li>
 * Valor da assinatura.
 * </li>
 * </ul>
 */

public class GeradorDeCertificados {

    /**
     * Gera a estrutura de informações de um certificado.
     *
     * @param chavePublica  chave pública do titular.
     * @param numeroDeSerie número de série do certificado.
     * @param nome          nome do titular.
     * @param nomeAc        nome da autoridade emissora.
     * @param dias          a partir da data atual, quantos dias de validade
     *                      terá o certificado.
     * @return Estrutura de informações do certificado.
     * <p>
     *
     * Algoritmo:
     * 1 - criar um V3TBSCertificateGenerator para construir a parte do certificado que será assinada
     * 2 - usar os métodos da classe para setar os argumentos dos parâmetros + assinatura
     * https://downloads.bouncycastle.org/java/docs/bcprov-jdk15to18-javadoc/org/bouncycastle/asn1/x509/V3TBSCertificateGenerator.html
     *
     */

    //https://magnus-k-karlsson.blogspot.com/2020/03/creating-x509-certificate-with-bouncy.html
    public TBSCertificate gerarEstruturaCertificado(PublicKey chavePublica,
                                                    int numeroDeSerie, String nome,
                                                    String nomeAc, int dias) {
        V3TBSCertificateGenerator tbs = new V3TBSCertificateGenerator();
        tbs.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(chavePublica.getEncoded()));
        tbs.setSerialNumber(new ASN1Integer(numeroDeSerie));
        tbs.setSubject(new X500Name(nome));
        tbs.setIssuer(new X500Name(nomeAc));

        Instant now = Instant.now(); //https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/time/Instant.html#now()
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(dias, ChronoUnit.DAYS)); //https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/time/temporal/ChronoUnit.html#DAYS
        tbs.setStartDate(new Time(notBefore));
        tbs.setEndDate(new Time(notAfter));

        tbs.setSignature(new DefaultSignatureAlgorithmIdentifierFinder().find(algoritmoAssinatura));

        return tbs.generateTBSCertificate();
    }

    /**
     * Gera valor da assinatura do certificado.
     *
     * @param estruturaCertificado estrutura de informações do certificado.
     * @param chavePrivadaAc       chave privada da AC que emitirá esse
     *                             certificado.
     * @return Bytes da assinatura.
     *
     * Algoritmo:
     * 1 - recebe os bytes do TBSCertificate e colocar em um array
     * 2 - instanciar uma assinatura, inicializá-la e alimentá-la com os dados
     * 3 - assinar e retornar um DERBitString
     */
    public DERBitString geraValorDaAssinaturaCertificado(TBSCertificate estruturaCertificado,
                                                         PrivateKey chavePrivadaAc) throws Exception {

            byte[] dados = estruturaCertificado.getEncoded(); //1

            //https://downloads.bouncycastle.org/java/docs/bcprov-jdk15to18-javadoc/org/bouncycastle/asn1/ocsp/Signature.html
            Signature signature = Signature.getInstance(algoritmoAssinatura);  //2
            signature.initSign(chavePrivadaAc);
            signature.update(dados);

            byte[] assinatura = signature.sign(); //3
            return new DERBitString(assinatura); //criando um DERBitString para retorno
    }

    /**
     * Gera um certificado.
     *
     * @param estruturaCertificado  estrutura de informações do certificado.
     * @param algoritmoDeAssinatura algoritmo de assinatura.
     * @param valorDaAssinatura     valor da assinatura.
     * @return Objeto que representa o certificado.
     * @see ASN1EncodableVector //criar um
     *
     * Algoritmo:
     * 1 - criar um objeto ASN1EncodableVector que vai conter os 3 componentes que estão nos parâmetros
     * 2 - colocar esse vetor em um DERSequence
     * 3 - converter essa sequência em um array de bytes
     * 4 - usar CertificateFactory para criar um X509Certificate a partir do array de bytes
     */
    public X509Certificate gerarCertificado(TBSCertificate estruturaCertificado,
                                            AlgorithmIdentifier algoritmoDeAssinatura,
                                            DERBitString valorDaAssinatura) throws Exception {

        //https://downloads.bouncycastle.org/java/docs/bcjce-jdk13-javadoc/org/bouncycastle/asn1/ASN1EncodableVector.html
        ASN1EncodableVector vetor = new ASN1EncodableVector(); //1
        vetor.add(estruturaCertificado);
        vetor.add(algoritmoDeAssinatura);
        vetor.add(valorDaAssinatura);

        //https://magnus-k-karlsson.blogspot.com/2020/03/creating-x509-certificate-with-bouncy.html
        DERSequence sequencia = new DERSequence(vetor); //2
        ByteArrayInputStream array = new ByteArrayInputStream(sequencia.getEncoded()); //3
        return (X509Certificate) CertificateFactory.getInstance(formatoCertificado).generateCertificate(array); // 4 https://docs.oracle.com/javase/8/docs/api/java/security/cert/CertificateFactory.html

    }

}
