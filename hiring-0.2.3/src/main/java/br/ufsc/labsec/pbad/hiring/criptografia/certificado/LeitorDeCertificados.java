package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por ler um certificado do disco.
 *
 * @see CertificateFactory
 */
public class LeitorDeCertificados {

    /**
     * Lê um certificado do local indicado.
     *
     * @param caminhoCertificado caminho do certificado a ser lido.
     * @return Objeto do certificado.
     *
     * Algoritmo:
     * Fiz o mesmo que em LeitorDeChaves
     * JcaX509CertificateConverter converte para X509Certificate
     *
     * Obs: X509CertificateHolder. Origem: Biblioteca Bouncy Castle. Uso: Quando você lê ou gera certificados. Representa: Um certificado imutável, usado antes da conversão para Java padrão.
     *      X509Certificate. Origem: Java padrão. Uso: Quando você valida, verifica assinaturas. Representa: Um certificado pronto para uso.
     */
    public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado) throws FileNotFoundException, IOException{

        File arquivoCertificado = new File(caminhoCertificado);
        try (FileReader certificadoReader = new FileReader(arquivoCertificado)){
            PEMParser pemParser = new PEMParser(certificadoReader);
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            X509CertificateHolder certificadoHolder = (X509CertificateHolder) pemParser.readObject();

            return converter.getCertificate(certificadoHolder);

        } catch (CertificateException | IOException e){
            System.err.println("Erro ao ler certificado");
            e.printStackTrace();
            return null;
        }
    }

}
