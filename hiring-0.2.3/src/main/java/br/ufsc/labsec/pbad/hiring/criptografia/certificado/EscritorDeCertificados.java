package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

/**
 * Classe responsável por escrever um certificado no disco.
 */
public class EscritorDeCertificados {

    /**
     * Escreve o certificado indicado no disco.
     *
     * @param nomeArquivo           caminho que será escrito o certificado.
     * @param certificadoCodificado bytes do certificado.
     *                              <p>
     * Algoritmo:
     * 1 - como entrada teremos um array de bytes, que representa o certificado codificado e precisamos colocar ele em formato pem
     * 2 - criar um writer
     * 3 - criar um JcaPEMWriter que vai converter o certificado para a representação pem e escrever no writer
     */
    public static void escreveCertificado(String nomeArquivo,
                                          byte[] certificadoCodificado) throws IOException {

        //https://downloads.bouncycastle.org/java/docs/bcprov-jdk15to18-javadoc/org/bouncycastle/util/io/pem/PemObject.html
        //"CERTIFICATE" serve como um identificador para objetos no formato pem
        PemObject certificadoCod = new PemObject("CERTIFICATE", certificadoCodificado);

        //https://downloads.bouncycastle.org/java/docs/bcpkix-jdk14-javadoc/org/bouncycastle/openssl/jcajce/JcaPEMWriter.html
        try (Writer writer = new FileWriter(nomeArquivo);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificadoCod);
        }

    }
}
