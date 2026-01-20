package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;


/**
 * <b>Terceira etapa - gerar certificados digitais</b>
 * <p>
 * Aqui você terá que gerar dois certificados digitais. A identidade ligada
 * a um dos certificados digitais deverá ser a sua. A entidade emissora do
 * seu certificado será a AC-Raiz, cuja chave privada já foi previamente
 * gerada. Também deverá ser feito o certificado digital para a AC-Raiz,
 * que deverá ser autoassinado.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * emitir um certificado digital autoassinado no formato X.509 para a AC-Raiz;
 * </li>
 * <li>
 * emitir um certificado digital no formato X.509, assinado pela AC-Raiz. O
 * certificado deve ter as seguintes características:
 * <ul>
 * <li>
 * {@code Subject} deverá ser o seu nome;
 * </li>
 * <li>
 * {@code SerialNumber} deverá ser o número da sua matrícula;
 * </li>
 * <li>
 * {@code Issuer} deverá ser a AC-Raiz.
 * </li>
 * </ul>
 * </li>
 * <li>
 * anexar ao desafio os certificados emitidos em formato PEM;
 * </li>
 * <li>
 * as chaves utilizadas nessa etapa deverão ser as mesmas já geradas.
 * </li>
 * </ul>
 */
public class TerceiraEtapa {

    public static void executarEtapa() {
        // TODO implementar
        try {

            PrivateKey chavePvAc = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaAc, algoritmoChave);
            PublicKey chavePuAc = LeitorDeChaves.lerChavePublicaDoDisco(caminhoChavePublicaAc, algoritmoChave);
            PublicKey minhaChavePu = LeitorDeChaves.lerChavePublicaDoDisco(caminhoChavePublicaUsuario, algoritmoChave);

            GeradorDeCertificados geradorCertificadoAC = new GeradorDeCertificados();

            AlgorithmIdentifier algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algoritmoAssinatura);

            assert chavePuAc != null;
            TBSCertificate acCertificado = geradorCertificadoAC.gerarEstruturaCertificado(chavePuAc, numeroSerieAc, nomeUsuario, nomeAcRaiz, 1000);

            DERBitString assinaturaAC = geradorCertificadoAC.geraValorDaAssinaturaCertificado(acCertificado, chavePvAc);
            X509Certificate certificadoAC = geradorCertificadoAC.gerarCertificado(acCertificado, algorithmIdentifier, assinaturaAC);

            EscritorDeCertificados.escreveCertificado(caminhoCertificadoAcRaiz, certificadoAC.getEncoded());
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            GeradorDeCertificados geradorCertificadoUsuario = new GeradorDeCertificados();

            assert minhaChavePu !=null;
            TBSCertificate meuCertificado = geradorCertificadoUsuario.gerarEstruturaCertificado(minhaChavePu, 24203054, "CN=Maria Eduarda Teixeira Costa", nomeAcRaiz, 1000);

            DERBitString assinaturaUsuario = geradorCertificadoUsuario.geraValorDaAssinaturaCertificado(meuCertificado, chavePvAc);
            X509Certificate certificadoUsuario = geradorCertificadoUsuario.gerarCertificado(meuCertificado, algorithmIdentifier, assinaturaUsuario);

            EscritorDeCertificados.escreveCertificado(caminhoCertificadoUsuario, certificadoUsuario.getEncoded());

            System.out.println("Etapa 3 check");

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
