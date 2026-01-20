package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import br.ufsc.labsec.pbad.hiring.Constantes;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


/**
 * Classe responsável por gerar um repositório de chaves PKCS#12.
 *
 * @see KeyStore
 *
 */

public class GeradorDeRepositorios {

    /**
     * Gera um PKCS#12 para a chave privada/certificado passados como parâmetro.
     *
     * @param chavePrivada  chave privada do titular do certificado.
     * @param certificado   certificado do titular.
     * @param caminhoPkcs12 caminho onde será escrito o PKCS#12.
     * @param alias         nome amigável dado à entrada do PKCS#12, que
     *                      comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     *
     * Com o import KeyStore descobri o que teria que usar
     * https://gist.github.com/jac18281828/f5cda08f7aa3b12b2b7e451c23dc7ed1
     */
   public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha) throws Exception {
           KeyStore keyStore = KeyStore.getInstance(Constantes.formatoRepositorio); //https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html
           keyStore.load(null, senha);

           X509Certificate[] certificate = new X509Certificate[] {certificado};

           keyStore.setKeyEntry(alias, chavePrivada, senha, certificate); //setar a entrada da chave com seus devidos parâmetros

           keyStore.store(new FileOutputStream(caminhoPkcs12), senha);
    }

}

